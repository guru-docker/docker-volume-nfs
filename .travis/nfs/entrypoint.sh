#!/bin/sh
# Export /exports/data to everyone and run an NFSv4-only server in the
# foreground. Deliberately permissive: this is a disposable test fixture.
set -eu

echo '/exports/data *(rw,sync,no_subtree_check,no_root_squash,fsid=0)' > /etc/exports

rpcbind -w
exportfs -ra
exportfs -v

rpc.nfsd --no-nfs-version 2 --no-nfs-version 3 8
exec rpc.mountd --foreground --no-nfs-version 2 --no-nfs-version 3
