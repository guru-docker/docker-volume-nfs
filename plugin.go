package main

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/docker/go-plugins-helpers/volume"
	"github.com/rs/zerolog/log"
)

type DockerVolume struct {
	Server string
	Path   string

	Options     []string
	Mountpoint  string
	connections int
}

type DockerDriver struct {
	sync.RWMutex

	root      string
	statePath string
	volumes   map[string]*DockerVolume

	// mount and unmount indirect through the real mount/umount helpers by
	// default; tests replace them to exercise the driver without a mount.
	mount   func(*DockerVolume) error
	unmount func(string) error
}

func newDockerDriver(root string) (*DockerDriver, error) {
	log.Info().Any("method", "new driver").Msg(root)

	d := &DockerDriver{
		root:      filepath.Join(root, "volumes"),
		statePath: filepath.Join(root, "state", "nfs-state.json"),
		volumes:   map[string]*DockerVolume{},
	}
	d.mount = d.mountVolume
	d.unmount = d.unmountVolume

	data, err := os.ReadFile(d.statePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Warn().Any("statePath", d.statePath).Msg("no state found")
		} else {
			return nil, logError("failed to read state: %w", err)
		}
	} else {
		if err = json.Unmarshal(data, &d.volumes); err != nil {
			return nil, logError("failed to unmarshal state: %w", err)
		}
	}

	return d, nil
}

func (d *DockerDriver) saveState() error {
	data, err := json.Marshal(d.volumes)
	if err != nil {
		return logError("failed to marshal state: %w", err)
	}

	if err = os.WriteFile(d.statePath, data, 0644); err != nil {
		return logError("failed to save state: %w", err)
	}

	return nil
}

func (d *DockerDriver) Create(r *volume.CreateRequest) error {
	log.Info().Any("method", "create").Msgf("%#v", r)

	d.Lock()
	defer d.Unlock()
	v := &DockerVolume{}

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

	return d.saveState()
}

func (d *DockerDriver) Remove(r *volume.RemoveRequest) error {
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
		return logError("%v", err)
	}
	delete(d.volumes, r.Name)

	return d.saveState()
}

func (d *DockerDriver) Path(r *volume.PathRequest) (*volume.PathResponse, error) {
	log.Info().Any("method", "path").Msgf("%#v", r)

	d.RLock()
	defer d.RUnlock()

	v, ok := d.volumes[r.Name]
	if !ok {
		return &volume.PathResponse{}, logError("volume %s not found", r.Name)
	}

	return &volume.PathResponse{Mountpoint: v.Mountpoint}, nil
}

func (d *DockerDriver) Mount(r *volume.MountRequest) (*volume.MountResponse, error) {
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
			if err = os.MkdirAll(v.Mountpoint, 0755); err != nil {
				return &volume.MountResponse{}, logError("%v", err)
			}
		} else if err != nil {
			return &volume.MountResponse{}, logError("%v", err)
		}

		if fi != nil && !fi.IsDir() {
			return &volume.MountResponse{}, logError("%v already exists and it's not a directory", v.Mountpoint)
		}

		if err = d.mount(v); err != nil {
			return &volume.MountResponse{}, logError("%v", err)
		}
	}

	v.connections++
	return &volume.MountResponse{Mountpoint: v.Mountpoint}, nil
}

func (d *DockerDriver) Unmount(r *volume.UnmountRequest) error {
	log.Info().Any("method", "unmount").Msgf("%#v", r)

	d.Lock()
	defer d.Unlock()
	v, ok := d.volumes[r.Name]
	if !ok {
		return logError("volume %s not found", r.Name)
	}

	v.connections--

	if v.connections <= 0 {
		if err := d.unmount(v.Mountpoint); err != nil {
			return logError("%v", err)
		}
		v.connections = 0
	}

	return nil
}

func (d *DockerDriver) Get(r *volume.GetRequest) (*volume.GetResponse, error) {
	log.Info().Any("method", "get").Msgf("%#v", r)

	d.Lock()
	defer d.Unlock()

	v, ok := d.volumes[r.Name]
	if !ok {
		return &volume.GetResponse{}, logError("volume %s not found", r.Name)
	}

	return &volume.GetResponse{Volume: &volume.Volume{Name: r.Name, Mountpoint: v.Mountpoint}}, nil
}

func (d *DockerDriver) List() (*volume.ListResponse, error) {
	log.Info().Any("method", "list").Msg("")

	d.Lock()
	defer d.Unlock()

	var vols []*volume.Volume
	for name, v := range d.volumes {
		vols = append(vols, &volume.Volume{Name: name, Mountpoint: v.Mountpoint})
	}
	return &volume.ListResponse{Volumes: vols}, nil
}

func (d *DockerDriver) Capabilities() *volume.CapabilitiesResponse {
	log.Info().Any("method", "capabilities").Msg("")

	return &volume.CapabilitiesResponse{Capabilities: volume.Capability{Scope: "local"}}
}

// nfsMountArgs renders the argument list passed to mount(8) for v, excluding
// the program name. Options are sorted so the result is stable.
func nfsMountArgs(v *DockerVolume) []string {
	args := []string{"-t", "nfs", fmt.Sprintf("%s:%s", v.Server, v.Path), v.Mountpoint}
	if len(v.Options) > 0 {
		opts := append([]string(nil), v.Options...)
		sort.Strings(opts)
		args = append(args, "-o", strings.Join(opts, ","))
	}
	return args
}

// mountVolume mounts the remote export at v.Mountpoint. This driver is an NFS
// client: exporting the share is the server's job, not ours.
func (d *DockerDriver) mountVolume(v *DockerVolume) error {
	cmd := exec.Command("mount", nfsMountArgs(v)...)

	log.Info().Any("method", "mountVolume").Msgf("Mount command: %v", cmd.Args)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return logError("nfs mount command failed: %v (%s) cmd: [%s]", err, output, cmd.String())
	}
	log.Info().Any("method", "mountVolume").Msg(string(output))

	return nil
}

func (d *DockerDriver) unmountVolume(target string) error {
	cmd := fmt.Sprintf("umount %s", target)
	log.Info().Any("method", "unmountVolume").Msgf("%v", cmd)
	return exec.Command("sh", "-c", cmd).Run()
}

func logError(format string, args ...interface{}) error {
	log.Error().Any("method", "logError").Msgf(format, args...)
	return fmt.Errorf(format, args...)
}
