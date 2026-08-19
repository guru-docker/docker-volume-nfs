# Throwaway NFS server used only by the integration tests.
# Must be run with --privileged; it relies on the host's nfsd kernel module.
FROM alpine:3.21

RUN apk add --no-cache nfs-utils \
	&& mkdir -p /exports/data \
	&& chmod 777 /exports/data

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 2049
ENTRYPOINT ["/entrypoint.sh"]
