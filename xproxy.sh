#!/bin/bash

DAEMON="/Users/chib/ops/xproxy/xproxy"
LOG_FILE="/Users/chib/ops/xproxy/xproxy.log"
PID_FILE="/Users/chib/ops/xproxy/xproxy.pid"

start() {
    if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        echo 'Service already running' >&2
        return 1
    fi

    echo 'Starting xproxy service...' >&2
    nohup $DAEMON -h 111.112.113.111 -p 22 -u chib -P afafaf -l 1080 -t 7890 > $LOG_FILE 2>&1 &
    #local CMD="nohup $DAEMON -h 111.112.113.111 -p 22 -u chib -P afafaf -l 1080 -t 7890 > $LOG_FILE 2>&1 &"
    #su - "$(whoami)" -c "$CMD"
    echo $! > "$PID_FILE"
    echo 'Service started' >&2
}

stop() {
    if [ ! -f "$PID_FILE" ] || ! kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        echo 'Service not running' >&2
        return 1
    fi

    echo 'Stopping service...' >&2
    kill -15 "$(cat "$PID_FILE")" && rm -f "$PID_FILE"
    echo 'Service stopped' >&2
}

case "${1:-''}" in
    'start')
        start
        ;;
    'stop')
        stop
        ;;
    'restart')
        stop
        start
        ;;
    *)
        echo "Usage: $0 {start|stop|restart}"
        exit 1
        ;;
esac
