#!/bin/sh
ACTION=$1
PID=$2
MAP_PATH=/sys/fs/bpf/pid_filter_map

if [ -z "$ACTION" ] || [ -z "$PID" ]; then
  echo "Usage: $0 {add|del} <pid>"
  exit 1
fi

hex=$(printf "%08x" "$PID")   # e.g. "00008a18"

# We should in order of <> <> <> <> to the bpftool
b1="0x$(echo "$hex" | cut -c7-8)"  # low byte
b2="0x$(echo "$hex" | cut -c5-6)"
b3="0x$(echo "$hex" | cut -c3-4)"
b4="0x$(echo "$hex" | cut -c1-2)"  # high byte

case "$ACTION" in
  add)
    bpftool map update pinned "$MAP_PATH" \
      key "$b1" "$b2" "$b3" "$b4" \
      value 1 \
    && echo "Blocking PID $PID" \
    || echo "Failed to block PID $PID"
    ;;
  del)
    bpftool map delete pinned "$MAP_PATH" \
      key "$b1" "$b2" "$b3" "$b4" \
    && echo "Unblocked PID $PID" \
    || echo "Failed to unblock PID $PID"
    ;;
  *)
    echo "Unknown action: $ACTION"
    exit 1
    ;;
esac

