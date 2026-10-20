#!/bin/sh
# usage: run_doip_demo.sh <doip_server_demo> <doip_client_demo> <uni|bi>
# Starts the DoIP ECU on a free-ish port, runs the tester against it, stops the ECU.
SERVER=$1 CLIENT=$2 MODE=$3
PORT=$((20000 + $$ % 20000))
LOG=$(mktemp)
"$SERVER" --port $PORT > "$LOG" 2>&1 &
SPID=$!
trap 'kill $SPID 2>/dev/null; rm -f "$LOG"' EXIT
i=0
until grep -q listening "$LOG"; do
    i=$((i + 1)); [ $i -gt 50 ] && { echo "server did not start"; cat "$LOG"; exit 1; }
    sleep 0.1
done
"$CLIENT" --port $PORT --mode "$MODE" || { RC=$?; echo "--- server log ---"; cat "$LOG"; exit $RC; }
