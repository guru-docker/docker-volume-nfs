#!/usr/bin/env bash
#
# End-to-end test for the NFS volume plugin.
#
# Builds the managed plugin, brings up an NFS server, then drives the plugin
# through the real Docker volume API. Every case writes through one container
# and reads back through another, so a silent no-op mount fails.
#
# Requires: docker with plugin support, permission to install plugins, and a
# host kernel with nfsd available (the server fixture runs --privileged).
# Point at an existing server instead with NFS_SERVER=... NFS_EXPORT=...
#
#   ./.travis/integration.sh
#
set -euo pipefail

cd "$(dirname "$0")/.."

DOCKER=${DOCKER:-docker}
PLUGIN_NAME=${PLUGIN_NAME:-glabservices/plugin-nfs}
PLUGIN_TAG=${PLUGIN_TAG:-test}
PLUGIN="${PLUGIN_NAME}:${PLUGIN_TAG}"
NFS_IMAGE=${NFS_IMAGE:-docker-volume-nfs-testserver}
NFS_EXPORT=${NFS_EXPORT:-/exports/data}
VOLUME=${VOLUME:-nfsvolume}

nfs_cid=""
failures=0

log()  { echo; echo "=== $*"; }
fail() { echo "!!! FAIL: $*" >&2; failures=$((failures + 1)); }

cleanup() {
	local rc=$?
	log "cleanup"
	$DOCKER volume rm -f "$VOLUME" >/dev/null 2>&1 || true
	[ -n "$nfs_cid" ] && $DOCKER rm -f "$nfs_cid" >/dev/null 2>&1 || true
	$DOCKER plugin disable -f "$PLUGIN" >/dev/null 2>&1 || true
	$DOCKER plugin rm -f "$PLUGIN" >/dev/null 2>&1 || true
	exit $rc
}
trap cleanup EXIT

# Creates a volume, writes through one container, reads back through another.
# Any extra arguments are passed to `docker volume create`.
roundtrip() {
	local name=$1; shift

	$DOCKER volume rm -f "$VOLUME" >/dev/null 2>&1 || true
	if ! $DOCKER volume create -d "$PLUGIN" "$@" "$VOLUME" >/dev/null; then
		fail "$name: volume create failed"
		return
	fi
	if ! $DOCKER run --rm -v "$VOLUME:/write" busybox \
		sh -c "echo hello > /write/probe"; then
		fail "$name: write failed"
		return
	fi
	if ! $DOCKER run --rm -v "$VOLUME:/read" busybox \
		grep -Fxq hello /read/probe; then
		fail "$name: readback failed"
		return
	fi
	$DOCKER volume rm -f "$VOLUME" >/dev/null 2>&1 || true
	echo "--- ok: $name"
}

log "pull fixtures"
$DOCKER pull -q busybox

log "build and enable plugin $PLUGIN"
PLUGIN_NAME="$PLUGIN_NAME" PLUGIN_TAG="$PLUGIN_TAG" DOCKER="$DOCKER" make
$DOCKER plugin enable "$PLUGIN"
$DOCKER plugin ls

if [ -n "${NFS_SERVER:-}" ]; then
	log "using external NFS server $NFS_SERVER:$NFS_EXPORT"
else
	log "start NFS server fixture"
	$DOCKER build -q -t "$NFS_IMAGE" .travis/nfs
	nfs_cid=$($DOCKER run -d --privileged "$NFS_IMAGE")
	NFS_SERVER=$($DOCKER inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$nfs_cid")
	if [ -z "$NFS_SERVER" ]; then
		echo "could not determine the NFS server address" >&2
		exit 1
	fi
	for _ in $(seq 30); do
		$DOCKER exec "$nfs_cid" sh -c 'exportfs -v >/dev/null 2>&1' && break
		sleep 1
	done
	echo "NFS server at $NFS_SERVER:$NFS_EXPORT"
fi

log "case: basic mount"
roundtrip "basic mount" -o server="$NFS_SERVER" -o path="$NFS_EXPORT"

log "case: explicit protocol version"
roundtrip "vers=4" -o server="$NFS_SERVER" -o path="$NFS_EXPORT" -o vers=4

log "case: server and path are required"
for opts in "-o server=$NFS_SERVER" "-o path=$NFS_EXPORT" ""; do
	# shellcheck disable=SC2086
	if $DOCKER volume create -d "$PLUGIN" $opts "$VOLUME" >/dev/null 2>&1; then
		fail "required options: 'docker volume create $opts' should have been rejected"
		$DOCKER volume rm -f "$VOLUME" >/dev/null 2>&1 || true
	fi
done
echo "--- ok: server and path are required"

log "case: sshfs-style options are rejected"
if $DOCKER volume create -d "$PLUGIN" \
	-o sshcmd=root@localhost:/ -o password=root "$VOLUME" >/dev/null 2>&1; then
	fail "sshfs options: volume create should have been rejected"
	$DOCKER volume rm -f "$VOLUME" >/dev/null 2>&1 || true
else
	echo "--- ok: sshfs-style options are rejected"
fi

log "case: volume is released after use"
$DOCKER volume create -d "$PLUGIN" \
	-o server="$NFS_SERVER" -o path="$NFS_EXPORT" "$VOLUME" >/dev/null
$DOCKER run --rm -v "$VOLUME:/mnt" busybox true
if ! $DOCKER volume rm "$VOLUME" >/dev/null; then
	fail "release: volume could not be removed after its container exited"
else
	echo "--- ok: volume is released after use"
fi

log "result"
if [ "$failures" -ne 0 ]; then
	echo "$failures case(s) failed" >&2
	exit 1
fi
echo "all cases passed"
