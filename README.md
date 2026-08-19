# Docker volume plugin for NFS

This plugin lets a container mount a remote NFS export as a Docker volume.

[![CI](https://github.com/guru-docker/docker-volume-nfs/actions/workflows/ci.yml/badge.svg)](https://github.com/guru-docker/docker-volume-nfs/actions/workflows/ci.yml)

The plugin is an NFS *client*. The export itself must already be published by
your NFS server; the plugin does not create or manage exports.

## Usage

1 - Install the plugin

```
$ docker plugin install glabservices/plugin-nfs

# or to enable debug
$ docker plugin install glabservices/plugin-nfs DEBUG=1

# or to change where plugin state is stored
$ docker plugin install glabservices/plugin-nfs state.source=<any_folder>
```

2 - Create a volume

> The export must already exist on the NFS server and be reachable from the
> Docker host, otherwise mounting the volume fails.

```
$ docker volume create -d glabservices/plugin-nfs \
    -o server=<host_or_ip> \
    -o path=<export_path> \
    [-o <any_mount_-o_option>] \
    nfsvolume
nfsvolume

$ docker volume ls
DRIVER                    VOLUME NAME
glabservices/plugin-nfs   nfsvolume
```

3 - Use the volume

```
$ docker run -it -v nfsvolume:<path> busybox ls <path>
```

## Options

| Option   | Required | Description                                            |
| -------- | -------- | ------------------------------------------------------ |
| `server` | yes      | NFS server hostname or IP address.                     |
| `path`   | yes      | Export path on that server, e.g. `/exports/data`.      |

Any other option is passed through to `mount -o`, so the usual NFS mount
options work:

```
$ docker volume create -d glabservices/plugin-nfs \
    -o server=10.0.0.5 -o path=/exports/data \
    -o vers=4 -o ro -o soft \
    nfsvolume
```

## Development

```
# unit tests and static checks
$ ./.travis/unit.sh

# build the managed plugin locally
$ make

# end-to-end tests (needs docker, plugin install rights and a host nfsd)
$ sudo ./.travis/integration.sh
```

`make` targets the local Docker engine by default. Override it with
`make DOCKER="docker --context=<name>"` to build against another engine, and
`PLUGIN_NAME` / `PLUGIN_TAG` to change what is built.

## LICENSE

MIT
