package main

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"github.com/docker/go-plugins-helpers/volume"
	"github.com/rs/zerolog/log"
)

type nfsVolume struct {
	Server      string
	Path        string
	Options     []string
	Mountpoint  string
	connections int
}

type nfsDriver struct {
	sync.RWMutex
	root      string
	statePath string
	volumes   map[string]*nfsVolume
}

func newNfsDriver(root string) (*nfsDriver, error) {
	log.Info().Any("method", "new driver").Msg(root)

	d := &nfsDriver{
		root:      filepath.Join(root, "volumes"),
		statePath: filepath.Join(root, "state", "nfs-state.json"),
		volumes:   map[string]*nfsVolume{},
	}

	data, err := os.ReadFile(d.statePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Debug().Any("statePath", d.statePath).Msg("no state found")
		} else {
			return nil, err
		}
	} else {
		if err := json.Unmarshal(data, &d.volumes); err != nil {
			return nil, err
		}
	}

	return d, nil
}

func (d *nfsDriver) saveState() {
	data, err := json.Marshal(d.volumes)
	if err != nil {
		log.Error().Any("statePath", d.statePath).Msg(err.Error())
		return
	}

	if err := os.WriteFile(d.statePath, data, 0644); err != nil {
		log.Error().Any("savestate", d.statePath).Msg(err.Error())
	}
}

func (d *nfsDriver) Create(r *volume.CreateRequest) error {
	log.Info().Any("method", "create").Msgf("%#v", r)

	d.Lock()
	defer d.Unlock()
	v := &nfsVolume{}

	for key, val := range r.Options {
		switch key {
		case "server":
			v.Server = val
		case "path":
			v.Path = val
		default:
			if val != "" {
				v.Options = append(v.Options, key+"="+val)
			} else {
				v.Options = append(v.Options, key)
			}
		}
	}

	if v.Server == "" || v.Path == "" {
		return logError("'server' and 'path' options are required")
	}

	v.Mountpoint = filepath.Join(d.root, fmt.Sprintf("%x", md5.Sum([]byte(v.Server+":"+v.Path))))
	d.volumes[r.Name] = v
	d.saveState()

	return nil
}

func (d *nfsDriver) Remove(r *volume.RemoveRequest) error {
	log.Info().Any("method", "remove").Msgf("%#v", r)

	d.Lock()
	defer d.Unlock()

	v, ok := d.volumes[r.Name]
	if !ok {
		return logError("volume %s not found", r.Name)
	}

	if v.connections != 0 {
		return logError("volume %s is currently used by a container", r.Name)
	}
	if err := os.RemoveAll(v.Mountpoint); err != nil {
		return logError(err.Error())
	}
	delete(d.volumes, r.Name)
	d.saveState()
	return nil
}

func (d *nfsDriver) Path(r *volume.PathRequest) (*volume.PathResponse, error) {
	log.Info().Any("method", "path").Msgf("%#v", r)

	d.RLock()
	defer d.RUnlock()

	v, ok := d.volumes[r.Name]
	if !ok {
		return &volume.PathResponse{}, logError("volume %s not found", r.Name)
	}

	return &volume.PathResponse{Mountpoint: v.Mountpoint}, nil
}

func (d *nfsDriver) Mount(r *volume.MountRequest) (*volume.MountResponse, error) {
	log.Info().Any("method", "mount").Msgf("%#v", r)

	d.Lock()
	defer d.Unlock()

	v, ok := d.volumes[r.Name]
	if !ok {
		return &volume.MountResponse{}, logError("volume %s not found", r.Name)
	}

	if v.connections == 0 {
		fi, err := os.Lstat(v.Mountpoint)
		if os.IsNotExist(err) {
			if err := os.MkdirAll(v.Mountpoint, 0755); err != nil {
				return &volume.MountResponse{}, logError(err.Error())
			}
		} else if err != nil {
			return &volume.MountResponse{}, logError(err.Error())
		}

		if fi != nil && !fi.IsDir() {
			return &volume.MountResponse{}, logError("%v already exists and it's not a directory", v.Mountpoint)
		}

		if err := d.mountVolume(v); err != nil {
			return &volume.MountResponse{}, logError(err.Error())
		}
	}

	v.connections++
	return &volume.MountResponse{Mountpoint: v.Mountpoint}, nil
}

func (d *nfsDriver) Unmount(r *volume.UnmountRequest) error {
	log.Info().Any("method", "unmount").Msgf("%#v", r)

	d.Lock()
	defer d.Unlock()
	v, ok := d.volumes[r.Name]
	if !ok {
		return logError("volume %s not found", r.Name)
	}

	v.connections--

	if v.connections <= 0 {
		if err := d.unmountVolume(v.Mountpoint); err != nil {
			return logError(err.Error())
		}
		v.connections = 0
	}

	return nil
}

func (d *nfsDriver) Get(r *volume.GetRequest) (*volume.GetResponse, error) {
	log.Info().Any("method", "get").Msgf("%#v", r)

	d.Lock()
	defer d.Unlock()

	v, ok := d.volumes[r.Name]
	if !ok {
		return &volume.GetResponse{}, logError("volume %s not found", r.Name)
	}

	return &volume.GetResponse{Volume: &volume.Volume{Name: r.Name, Mountpoint: v.Mountpoint}}, nil
}

func (d *nfsDriver) List() (*volume.ListResponse, error) {
	log.Info().Any("method", "list").Msg("")

	d.Lock()
	defer d.Unlock()

	var vols []*volume.Volume
	for name, v := range d.volumes {
		vols = append(vols, &volume.Volume{Name: name, Mountpoint: v.Mountpoint})
	}
	return &volume.ListResponse{Volumes: vols}, nil
}

func (d *nfsDriver) Capabilities() *volume.CapabilitiesResponse {
	log.Info().Any("method", "capabilities").Msg("")

	return &volume.CapabilitiesResponse{Capabilities: volume.Capability{Scope: "local"}}
}

func (d *nfsDriver) mountVolume(v *nfsVolume) error {
	cmd := exec.Command("mount", "-t", "nfs", fmt.Sprintf("%s:%s", v.Server, v.Path), v.Mountpoint)

	// Append default options like `rw` and `vers=4`
	//cmd.Args = append(cmd.Args, "-o", "rw,vers=4")

	// Include any additional options specified by the user
	for _, option := range v.Options {
		cmd.Args = append(cmd.Args, "-o", option)
	}

	log.Info().Any("method", "mountVolume").Msgf("Mount command: %v", cmd.Args)
	if output, err := cmd.CombinedOutput(); err != nil {
		return logError("nfs mount command failed: %v (%s)", err, output)
	} else {
		log.Info().Any("method", "mountVolume").Msg(string(output))
	}
	return nil
}

func (d *nfsDriver) unmountVolume(target string) error {
	cmd := fmt.Sprintf("umount %s", target)
	log.Info().Any("method", "unmountVolume").Msgf("%v", cmd)
	return exec.Command("sh", "-c", cmd).Run()
}

func logError(format string, args ...interface{}) error {
	log.Info().Any("method", "logError").Msgf(format, args...)
	return fmt.Errorf(format, args...)
}
