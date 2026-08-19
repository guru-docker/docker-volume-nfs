package main

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/docker/go-plugins-helpers/volume"
	"github.com/rs/zerolog"
)

func TestMain(m *testing.M) {
	// The driver logs unconditionally at debug level; keep test output readable.
	zerolog.SetGlobalLevel(zerolog.Disabled)
	os.Exit(m.Run())
}

// newTestDriver returns a driver rooted in a temporary directory, with the
// mount helpers stubbed out so no real mount(8) is ever invoked.
func newTestDriver(t *testing.T) *DockerDriver {
	t.Helper()

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "state"), 0755); err != nil {
		t.Fatalf("prepare state dir: %v", err)
	}

	d, err := newDockerDriver(root)
	if err != nil {
		t.Fatalf("newDockerDriver: %v", err)
	}

	d.mount = func(*DockerVolume) error { return nil }
	d.unmount = func(string) error { return nil }

	return d
}

func mustCreate(t *testing.T, d *DockerDriver, name string, opts map[string]string) {
	t.Helper()
	if err := d.Create(&volume.CreateRequest{Name: name, Options: opts}); err != nil {
		t.Fatalf("Create(%s): %v", name, err)
	}
}

// --- construction and state ------------------------------------------------

func TestNewDockerDriver_NoStateFileStartsEmpty(t *testing.T) {
	d := newTestDriver(t)

	if len(d.volumes) != 0 {
		t.Fatalf("expected no volumes, got %d", len(d.volumes))
	}
}

func TestNewDockerDriver_LoadsExistingState(t *testing.T) {
	root := t.TempDir()
	statePath := filepath.Join(root, "state", "nfs-state.json")
	if err := os.MkdirAll(filepath.Dir(statePath), 0755); err != nil {
		t.Fatal(err)
	}
	state := `{"vol1":{"Server":"10.0.0.5","Path":"/exports/data","Mountpoint":"/mnt/volumes/abc"}}`
	if err := os.WriteFile(statePath, []byte(state), 0644); err != nil {
		t.Fatal(err)
	}

	d, err := newDockerDriver(root)
	if err != nil {
		t.Fatalf("newDockerDriver: %v", err)
	}

	v, ok := d.volumes["vol1"]
	if !ok {
		t.Fatal("vol1 not loaded from state")
	}
	if v.Server != "10.0.0.5" || v.Path != "/exports/data" {
		t.Errorf("loaded %+v", v)
	}
}

func TestNewDockerDriver_CorruptStateIsAnError(t *testing.T) {
	root := t.TempDir()
	statePath := filepath.Join(root, "state", "nfs-state.json")
	if err := os.MkdirAll(filepath.Dir(statePath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, []byte("{not json"), 0644); err != nil {
		t.Fatal(err)
	}

	if _, err := newDockerDriver(root); err == nil {
		t.Fatal("expected an error for corrupt state, got nil")
	}
}

func TestCreate_PersistsAcrossRestart(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "state"), 0755); err != nil {
		t.Fatal(err)
	}

	d, err := newDockerDriver(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Create(&volume.CreateRequest{
		Name:    "vol1",
		Options: map[string]string{"server": "10.0.0.5", "path": "/exports/data"},
	}); err != nil {
		t.Fatal(err)
	}

	reloaded, err := newDockerDriver(root)
	if err != nil {
		t.Fatal(err)
	}
	v, ok := reloaded.volumes["vol1"]
	if !ok {
		t.Fatal("vol1 did not survive a driver restart")
	}
	if v.Server != "10.0.0.5" || v.Path != "/exports/data" {
		t.Errorf("reloaded %+v", v)
	}
}

// --- Create ----------------------------------------------------------------

func TestCreate_RequiresServerAndPath(t *testing.T) {
	tests := []struct {
		name string
		opts map[string]string
	}{
		{"neither", map[string]string{"ro": ""}},
		{"server only", map[string]string{"server": "10.0.0.5"}},
		{"path only", map[string]string{"path": "/exports/data"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := newTestDriver(t)

			err := d.Create(&volume.CreateRequest{Name: "vol1", Options: tt.opts})
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), "server") || !strings.Contains(err.Error(), "path") {
				t.Errorf("error %q does not name the required options", err)
			}
			if _, exists := d.volumes["vol1"]; exists {
				t.Error("a rejected volume must not be recorded")
			}
		})
	}
}

// TestCreate_RejectsSshfsStyleOptions is a regression guard for the copy-pasted
// integration script, which drove this plugin with sshfs options.
func TestCreate_RejectsSshfsStyleOptions(t *testing.T) {
	d := newTestDriver(t)

	err := d.Create(&volume.CreateRequest{
		Name:    "sshvolume",
		Options: map[string]string{"sshcmd": "root@localhost:/", "password": "root", "port": "2222"},
	})
	if err == nil {
		t.Fatal("expected sshfs-style options to be rejected by the NFS driver")
	}
}

func TestCreate_ParsesKnownOptions(t *testing.T) {
	d := newTestDriver(t)
	mustCreate(t, d, "vol1", map[string]string{
		"server": "10.0.0.5",
		"path":   "/exports/data",
	})

	v := d.volumes["vol1"]
	if v.Server != "10.0.0.5" {
		t.Errorf("Server = %q", v.Server)
	}
	if v.Path != "/exports/data" {
		t.Errorf("Path = %q", v.Path)
	}
	if len(v.Options) != 0 {
		t.Errorf("known options leaked into Options: %v", v.Options)
	}
}

func TestCreate_PassesThroughUnknownOptions(t *testing.T) {
	d := newTestDriver(t)
	mustCreate(t, d, "vol1", map[string]string{
		"server": "10.0.0.5",
		"path":   "/exports/data",
		"ro":     "",
		"vers":   "4",
	})

	got := append([]string(nil), d.volumes["vol1"].Options...)
	sort.Strings(got)
	want := []string{"ro", "vers=4"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Options = %v, want %v", got, want)
	}
}

func TestCreate_MountpointIsMD5OfServerAndPath(t *testing.T) {
	d := newTestDriver(t)
	mustCreate(t, d, "vol1", map[string]string{"server": "10.0.0.5", "path": "/exports/data"})

	want := filepath.Join(d.root, "06e086a9a2a8bbd15cb21e3a7953f418")
	if got := d.volumes["vol1"].Mountpoint; got != want {
		t.Errorf("Mountpoint = %q, want %q", got, want)
	}
}

// --- Mount / Unmount -------------------------------------------------------

func TestMount_CreatesMountpointAndMounts(t *testing.T) {
	d := newTestDriver(t)
	mustCreate(t, d, "vol1", map[string]string{"server": "10.0.0.5", "path": "/exports/data"})

	var mounted int
	d.mount = func(*DockerVolume) error { mounted++; return nil }

	resp, err := d.Mount(&volume.MountRequest{Name: "vol1"})
	if err != nil {
		t.Fatalf("Mount: %v", err)
	}
	if mounted != 1 {
		t.Errorf("mount helper called %d times, want 1", mounted)
	}
	if fi, err := os.Stat(resp.Mountpoint); err != nil || !fi.IsDir() {
		t.Errorf("mountpoint directory was not created: %v", err)
	}
	if d.volumes["vol1"].connections != 1 {
		t.Errorf("connections = %d, want 1", d.volumes["vol1"].connections)
	}
}

func TestMount_SecondMountDoesNotRemount(t *testing.T) {
	d := newTestDriver(t)
	mustCreate(t, d, "vol1", map[string]string{"server": "10.0.0.5", "path": "/exports/data"})

	var mounted int
	d.mount = func(*DockerVolume) error { mounted++; return nil }

	for i := 0; i < 3; i++ {
		if _, err := d.Mount(&volume.MountRequest{Name: "vol1"}); err != nil {
			t.Fatalf("Mount %d: %v", i, err)
		}
	}

	if mounted != 1 {
		t.Errorf("mount helper called %d times, want 1", mounted)
	}
	if d.volumes["vol1"].connections != 3 {
		t.Errorf("connections = %d, want 3", d.volumes["vol1"].connections)
	}
}

func TestMount_RejectsMountpointThatIsAFile(t *testing.T) {
	d := newTestDriver(t)
	mustCreate(t, d, "vol1", map[string]string{"server": "10.0.0.5", "path": "/exports/data"})

	mp := d.volumes["vol1"].Mountpoint
	if err := os.MkdirAll(filepath.Dir(mp), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mp, []byte("not a directory"), 0644); err != nil {
		t.Fatal(err)
	}

	d.mount = func(*DockerVolume) error {
		t.Error("mount helper must not run when the mountpoint is a file")
		return nil
	}

	if _, err := d.Mount(&volume.MountRequest{Name: "vol1"}); err == nil {
		t.Fatal("expected an error when the mountpoint is a regular file")
	}
}

func TestMount_PropagatesMountFailure(t *testing.T) {
	d := newTestDriver(t)
	mustCreate(t, d, "vol1", map[string]string{"server": "10.0.0.5", "path": "/exports/data"})

	d.mount = func(*DockerVolume) error { return os.ErrPermission }

	if _, err := d.Mount(&volume.MountRequest{Name: "vol1"}); err == nil {
		t.Fatal("expected the mount failure to surface")
	}
	if d.volumes["vol1"].connections != 0 {
		t.Errorf("connections = %d after a failed mount, want 0", d.volumes["vol1"].connections)
	}
}

func TestMount_UnknownVolume(t *testing.T) {
	d := newTestDriver(t)

	if _, err := d.Mount(&volume.MountRequest{Name: "nope"}); err == nil {
		t.Fatal("expected an error for an unknown volume")
	}
}

func TestUnmount_KeepsMountWhileOtherContainersHoldIt(t *testing.T) {
	d := newTestDriver(t)
	mustCreate(t, d, "vol1", map[string]string{"server": "10.0.0.5", "path": "/exports/data"})

	d.unmount = func(string) error {
		t.Error("must not unmount while another container holds the volume")
		return nil
	}

	for i := 0; i < 2; i++ {
		if _, err := d.Mount(&volume.MountRequest{Name: "vol1"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.Unmount(&volume.UnmountRequest{Name: "vol1"}); err != nil {
		t.Fatalf("Unmount: %v", err)
	}

	if d.volumes["vol1"].connections != 1 {
		t.Errorf("connections = %d, want 1", d.volumes["vol1"].connections)
	}
}

func TestUnmount_UnmountsOnLastReference(t *testing.T) {
	d := newTestDriver(t)
	mustCreate(t, d, "vol1", map[string]string{"server": "10.0.0.5", "path": "/exports/data"})

	var unmounted []string
	d.unmount = func(target string) error {
		unmounted = append(unmounted, target)
		return nil
	}

	if _, err := d.Mount(&volume.MountRequest{Name: "vol1"}); err != nil {
		t.Fatal(err)
	}
	if err := d.Unmount(&volume.UnmountRequest{Name: "vol1"}); err != nil {
		t.Fatalf("Unmount: %v", err)
	}

	want := []string{d.volumes["vol1"].Mountpoint}
	if !reflect.DeepEqual(unmounted, want) {
		t.Errorf("unmounted = %v, want %v", unmounted, want)
	}
}

func TestUnmount_UnknownVolume(t *testing.T) {
	d := newTestDriver(t)

	if err := d.Unmount(&volume.UnmountRequest{Name: "nope"}); err == nil {
		t.Fatal("expected an error for an unknown volume")
	}
}

// --- Remove ----------------------------------------------------------------

func TestRemove_UnknownVolume(t *testing.T) {
	d := newTestDriver(t)

	if err := d.Remove(&volume.RemoveRequest{Name: "nope"}); err == nil {
		t.Fatal("expected an error for an unknown volume")
	}
}

func TestRemove_RejectsVolumeInUse(t *testing.T) {
	d := newTestDriver(t)
	mustCreate(t, d, "vol1", map[string]string{"server": "10.0.0.5", "path": "/exports/data"})
	if _, err := d.Mount(&volume.MountRequest{Name: "vol1"}); err != nil {
		t.Fatal(err)
	}

	if err := d.Remove(&volume.RemoveRequest{Name: "vol1"}); err == nil {
		t.Fatal("expected an error when removing a volume that is in use")
	}
	if _, exists := d.volumes["vol1"]; !exists {
		t.Error("volume must survive a rejected Remove")
	}
}

func TestRemove_DeletesMountpointAndState(t *testing.T) {
	d := newTestDriver(t)
	mustCreate(t, d, "vol1", map[string]string{"server": "10.0.0.5", "path": "/exports/data"})
	mp := d.volumes["vol1"].Mountpoint
	if err := os.MkdirAll(mp, 0755); err != nil {
		t.Fatal(err)
	}

	if err := d.Remove(&volume.RemoveRequest{Name: "vol1"}); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	if _, exists := d.volumes["vol1"]; exists {
		t.Error("volume still present after Remove")
	}
	if _, err := os.Stat(mp); !os.IsNotExist(err) {
		t.Errorf("mountpoint still exists after Remove: %v", err)
	}
}

// --- read-only endpoints ---------------------------------------------------

func TestPathAndGet(t *testing.T) {
	d := newTestDriver(t)
	mustCreate(t, d, "vol1", map[string]string{"server": "10.0.0.5", "path": "/exports/data"})
	want := d.volumes["vol1"].Mountpoint

	p, err := d.Path(&volume.PathRequest{Name: "vol1"})
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	if p.Mountpoint != want {
		t.Errorf("Path.Mountpoint = %q, want %q", p.Mountpoint, want)
	}

	g, err := d.Get(&volume.GetRequest{Name: "vol1"})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if g.Volume.Name != "vol1" || g.Volume.Mountpoint != want {
		t.Errorf("Get returned %+v", g.Volume)
	}
}

func TestPathAndGet_UnknownVolume(t *testing.T) {
	d := newTestDriver(t)

	if _, err := d.Path(&volume.PathRequest{Name: "nope"}); err == nil {
		t.Error("Path: expected an error for an unknown volume")
	}
	if _, err := d.Get(&volume.GetRequest{Name: "nope"}); err == nil {
		t.Error("Get: expected an error for an unknown volume")
	}
}

func TestList(t *testing.T) {
	d := newTestDriver(t)
	mustCreate(t, d, "vol1", map[string]string{"server": "10.0.0.5", "path": "/exports/data"})
	mustCreate(t, d, "vol2", map[string]string{"server": "10.0.0.6", "path": "/exports/other"})

	resp, err := d.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(resp.Volumes) != 2 {
		t.Fatalf("List returned %d volumes, want 2", len(resp.Volumes))
	}
}

func TestCapabilities(t *testing.T) {
	d := newTestDriver(t)

	if scope := d.Capabilities().Capabilities.Scope; scope != "local" {
		t.Errorf("scope = %q, want local", scope)
	}
}

// --- mount(8) argument construction ----------------------------------------

func TestNFSMountArgs(t *testing.T) {
	tests := []struct {
		name string
		vol  DockerVolume
		want []string
	}{
		{
			name: "no options",
			vol:  DockerVolume{Server: "10.0.0.5", Path: "/exports/data", Mountpoint: "/mnt/volumes/x"},
			want: []string{"-t", "nfs", "10.0.0.5:/exports/data", "/mnt/volumes/x"},
		},
		{
			name: "with options",
			vol: DockerVolume{
				Server:     "10.0.0.5",
				Path:       "/exports/data",
				Mountpoint: "/mnt/volumes/x",
				Options:    []string{"ro", "vers=4"},
			},
			want: []string{"-t", "nfs", "10.0.0.5:/exports/data", "/mnt/volumes/x", "-o", "ro,vers=4"},
		},
		{
			name: "options are sorted for a stable command line",
			vol: DockerVolume{
				Server:     "10.0.0.5",
				Path:       "/exports/data",
				Mountpoint: "/mnt/volumes/x",
				Options:    []string{"vers=4", "soft", "ro"},
			},
			want: []string{"-t", "nfs", "10.0.0.5:/exports/data", "/mnt/volumes/x", "-o", "ro,soft,vers=4"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := nfsMountArgs(&tt.vol); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("nfsMountArgs() = %v, want %v", got, tt.want)
			}
		})
	}
}

// The connection count is unexported, so encoding/json drops it. After a restart
// every volume looks unused, letting Remove delete a mountpoint still in use.
func TestKnownIssue_StateDoesNotPersistConnectionCount(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "state"), 0755); err != nil {
		t.Fatal(err)
	}

	d, err := newDockerDriver(root)
	if err != nil {
		t.Fatal(err)
	}
	d.mount = func(*DockerVolume) error { return nil }
	if err := d.Create(&volume.CreateRequest{
		Name:    "vol1",
		Options: map[string]string{"server": "10.0.0.5", "path": "/exports/data"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Mount(&volume.MountRequest{Name: "vol1"}); err != nil {
		t.Fatal(err)
	}
	if err := d.saveState(); err != nil {
		t.Fatal(err)
	}

	reloaded, err := newDockerDriver(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := reloaded.volumes["vol1"].connections; got != 0 {
		t.Fatalf("connections survived a restart (%d) — the persistence bug looks fixed; update this test", got)
	}
}

// nfsMountArgs must not reorder the caller's slice in place; Mount holds the
// driver lock but the volume is shared with the persisted state.
func TestNFSMountArgs_DoesNotMutateVolumeOptions(t *testing.T) {
	v := &DockerVolume{
		Server:     "10.0.0.5",
		Path:       "/exports/data",
		Mountpoint: "/mnt/volumes/x",
		Options:    []string{"vers=4", "ro"},
	}

	nfsMountArgs(v)

	want := []string{"vers=4", "ro"}
	if !reflect.DeepEqual(v.Options, want) {
		t.Errorf("Options = %v, want %v", v.Options, want)
	}
}

// vers= is a client mount option and must reach mount(8) untouched. It was
// previously stripped because the driver also rendered an /etc/exports entry,
// where the option is not valid; that server-side path is gone.
func TestNFSMountArgs_PassesVersThrough(t *testing.T) {
	v := &DockerVolume{
		Server:     "10.0.0.5",
		Path:       "/exports/data",
		Mountpoint: "/mnt/volumes/x",
		Options:    []string{"vers=4.1"},
	}

	args := nfsMountArgs(v)
	if !slices.Contains(args, "vers=4.1") {
		t.Errorf("vers=4.1 did not survive into the mount arguments: %v", args)
	}
}
