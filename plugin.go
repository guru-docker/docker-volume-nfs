package main

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
}

func newDockerDriver(root string) (*DockerDriver, error) {
	log.Info().Any("method", "new driver").Msg(root)

	d := &DockerDriver{
		root:      filepath.Join(root, "volumes"),
		statePath: filepath.Join(root, "state", "nfs-state.json"),
		volumes:   map[string]*DockerVolume{},
	}

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
		return logError(err.Error())
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
				return &volume.MountResponse{}, logError(err.Error())
			}
		} else if err != nil {
			return &volume.MountResponse{}, logError(err.Error())
		}

		if fi != nil && !fi.IsDir() {
			return &volume.MountResponse{}, logError("%v already exists and it's not a directory", v.Mountpoint)
		}

		if err = d.mountVolume(v); err != nil {
			return &volume.MountResponse{}, logError(err.Error())
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
		if err := d.unmountVolume(v.Mountpoint); err != nil {
			return logError(err.Error())
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

func (d *DockerDriver) mountVolume(v *DockerVolume) (err error) {
	log.Info().Any("method", "mountVolume").Msgf("Creating directory: %s", v.Mountpoint)

	err = os.MkdirAll(v.Path, 0777)
	if err != nil {
		return logError("failed to create mountpoint: %v", err)
	}

	sort.Strings(v.Options)
	// Construct the export entry to add to /etc/exports
	exportEntry := fmt.Sprintf("%s %s/24(%s,no_subtree_check,no_root_squash)", v.Path, v.Server, strings.Join(v.Options, ","))

	re := regexp.MustCompile(`,?vers=[34]`)
	exportEntry = re.ReplaceAllString(exportEntry, "") // Add the export entry to /etc/exports
	err = d.addExportEntry(exportEntry)
	if err != nil {
		return logError("failed to add NFS export entry: %v", err)
	}

	// Reload NFS exports to apply changes
	exportfs := exec.Command("exportfs", "-ra")
	output, err := exportfs.CombinedOutput()
	if err != nil {
		return logError("failed to reload NFS exports: %v (%s) [%s]", err, string(output), exportEntry)
	}

	// Prepare the mount command
	cmd := exec.Command("mount", "-t", "nfs", fmt.Sprintf("%s:%s", v.Server, v.Path), v.Mountpoint)

	// Append any additional options for the mount command
	if len(v.Options) > 0 {
		cmd.Args = append(cmd.Args, "-o", strings.Join(v.Options, ","))
	}

	log.Info().Any("method", "mountVolume").Msgf("Mount command: %v", cmd.Args)
	if output, err = cmd.CombinedOutput(); err != nil {
		return logError("nfs mount command failed: %v (%s) cmd: [%s]", err, output, cmd.String())
	} else {
		log.Info().Any("method", "mountVolume").Msg(string(output))
	}
	return nil
}

func (d *DockerDriver) unmountVolume(target string) error {
	cmd := fmt.Sprintf("umount %s", target)
	log.Info().Any("method", "unmountVolume").Msgf("%v", cmd)
	return exec.Command("sh", "-c", cmd).Run()
}

func (d *DockerDriver) addExportEntry(entry string) error {
	// Log start of function execution
	log.Info().Any("method", "addExportEntry").Msgf("Starting to add NFS export entry %s", entry)

	// Read the current content of /etc/exports
	data, err := os.ReadFile("/etc/exports")
	if err != nil {
		log.Error().Any("method", "addExportEntry").Msgf("Failed to read /etc/exports: %v (%s)", err, entry)
		return logError("could not read /etc/exports: %w", err)
	}

	// Check if the entry already exists to avoid duplicates
	if strings.Contains(string(data), entry) {
		log.Info().Any("method", "addExportEntry").Msgf("Export entry already exists in /etc/exports (%s)", entry)
		return nil
	}

	// Open /etc/exports in append mode for writing the new entry
	f, err := os.OpenFile("/etc/exports", os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return logError("could not open /etc/exports for writing: %w", err)
	}
	defer f.Close()

	// Write the new entry to the file
	if _, err = f.WriteString(entry + "\n"); err != nil {
		return logError("could not write to /etc/exports: %w", err)
	}

	// Confirm the entry has been added
	log.Info().Any("method", "addExportEntry").Msgf("Successfully added NFS export entry: %s", entry)

	// Read back the file to verify the addition (optional debugging step)
	updatedData, readErr := os.ReadFile("/etc/exports")
	if readErr != nil {
		return logError("Failed to re-read /etc/exports after writing: %v", readErr)
	} else if !strings.Contains(string(updatedData), entry) {
		return logError("Verification failed: entry not found in /etc/exports after writing (%s)", string(updatedData))
	} else {
		log.Info().Any("method", "addExportEntry").Msgf("Verification successful: entry confirmed in /etc/exports (%s)", string(updatedData))
	}

	return nil
}

func logError(format string, args ...interface{}) error {
	log.Error().Any("method", "logError").Msgf(format, args...)
	return fmt.Errorf(format, args...)
}
