#!/bin/sh
set -e

echo "Loading & attaching eBPF programs…"
/loader /filter.o &
echo "eBPF programs loaded and attached."

echo "Pinning pid_filter_map for userspace access…"
MAP_ID=$(bpftool map show \
    | awk '/pid_filter_map/ { sub(":", "", $1); print $1; exit }')

if [ -z "$MAP_ID" ]; then
  echo "pid_filter_map not found"
  exit 1
fi

bpftool map pin id "$MAP_ID" /sys/fs/bpf/pid_filter_map
echo "pid_filter_map pinned at /sys/fs/bpf/pid_filter_map"

echo "Starting Java application…"
exec java -jar /vulnerable-app.jar

