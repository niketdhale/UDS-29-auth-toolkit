#!/bin/sh
# usage: run_can_demo.sh <can_server_demo> <can_client_demo> <uni|bi> [interface]
# Needs a CAN interface (e.g. vcan0, see docs/transports.md). Not a ctest: CI runs it where vcan is available.
SERVER=$1 CLIENT=$2 MODE=$3 IF=${4:-vcan0}
LOG=$(mktemp)
"$SERVER" --if "$IF" > "$LOG" 2>&1 &
SPID=$!
trap 'kill $SPID 2>/dev/null; rm -f "$LOG"' EXIT
i=0
until grep -q ISO-TP "$LOG"; do
    i=$((i + 1)); [ $i -gt 50 ] && { echo "server did not start"; cat "$LOG"; exit 1; }
    sleep 0.1
done
"$CLIENT" --if "$IF" --mode "$MODE" || { RC=$?; echo "--- server log ---"; cat "$LOG"; exit $RC; }
