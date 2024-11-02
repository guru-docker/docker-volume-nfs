FROM golang:1.23.2-alpine as builder
ADD . /go/src/github.com/guru-docker/docker-volume-nfs
WORKDIR /go/src/github.com/guru-docker/docker-volume-nfs

RUN apk add --no-cache --virtual .build-deps gcc libc-dev
RUN go install --ldflags '-extldflags "-static"'
RUN apk del .build-deps

CMD ["/go/bin/docker-volume-nfs"]


FROM alpine

RUN apk update && apk add nfs-utils
RUN mkdir -p /run/docker/plugins /mnt/state /mnt/volumes

COPY --from=builder /go/bin/docker-volume-nfs .
CMD ["docker-volume-nfs"]
