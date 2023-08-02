#!/bin/sh
echo "[*] Starting Wiki"
/usr/local/bin/start_tiddlywiki &
echo "[*] Starting dummy server" 
python3 /servers/dummy_server.py &
echo "[*] Starting ARPS server"
python3 /servers/server.py