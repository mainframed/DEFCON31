#!/bin/bash

RED="\e[31m"
ENDCOLOR="\e[0m"
GREEN="\e[32m"
BOLDGREEN="\e[1;${GREEN}m"

clear
echo -e "${RED}"
echo ''; echo ''
echo '________  _______________________________ _______    _______   '
echo '\______ \ \_   _____/\_   _____/\_   ___ \\   _  \   \      \  '
echo ' |    |  \ |    __)_  |    __)  /    \  \//  /_\  \  /   |   \ '
echo ' |    `   \|        \ |     \   \     \___\  \_/   \/    |    \'
echo '/_______  /_______  / \___  /    \______  /\_____  /\____|__  /'
echo '        \/        \/      \/            \/       \/         \/ '
echo '                   ________    ____                            '
echo '                   \_____  \  /_   |                           '
echo '                     _(__  <   |   |                           '
echo '                    /       \  |   |                           '
echo '                   /______  /  |___|                           '
echo '                          \/                                   '
echo -e "${ENDCOLOR}${BOLDGREEN}"; echo ''
echo "[+] Creating Labs folder"
[ ! -d "~/Labs" ] && mkdir Labs
echo "[+] Cloning Nmap"
[ ! -d "~/Labs/nmap" ] && git clone https://github.com/nmap/nmap.git ~/Labs/nmap
echo "[+] Restarting docker containers"
docker kill defcon31 &>/dev/null
docker rm defcon31 &>/dev/null
wget -O ~Labs/dummy_client.py "https://raw.githubusercontent.com/mainframed/DEFCON31/main/dummy_client.py"
ARCH=$(dpkg --print-architecture)
if [ "$ARCH" = "amd64" ]; then
    wget -O ~/Labs/client "https://github.com/mainframed/DEFCON31/raw/main/client_amd64" 
    docker run -d --name defcon31 -p 127.0.0.1:1234:1234 -p 127.0.0.1:31337:31337 mainframed767/defcon31:amd64
elif [ "$ARCH" = "arm64" ]
    wget -O ~/Labs/client "https://github.com/mainframed/DEFCON31/raw/main/client_arm64" 
    docker run -d --name defcon31 -p 127.0.0.1:1234:1234 -p 127.0.0.1:31337:31337 mainframed767/defcon31:arm64
else
    echo "${RED}ERROR ERROR ERROR"
    echo " Talk to the instructor about this error"
    echo "ERROR ERROR ERROR"
echo "${ENDCOLOR}"