ARG ARCH="amd64"
ARG OS="linux"
FROM quay.io/prometheus/busybox-${OS}-${ARCH}:latest
LABEL maintainer="The Prometheus Authors <prometheus-developers@googlegroups.com>"

ARG ARCH="amd64"
ARG OS="linux"
COPY .build/${OS}-${ARCH}/freeswitch_exporter /bin/freeswitch_exporter

USER       nobody
ENTRYPOINT ["/bin/freeswitch_exporter"]
EXPOSE 9282
