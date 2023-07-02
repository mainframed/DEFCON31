#!/bin/bash

RED="\e[31m"
ENDCOLOR="\e[0m"
GREEN="\e[32m"
BOLDGREEN="\e[1;${GREEN}m"

function clean_docker {
    echo "[+] Listing containers..."
    containers=$(docker ps -qa)
    echo "[+] containers: $containers"

    if [ ! -z "$containers" ]
    then
        echo "[+] Stopping containers..."
        docker stop $containers
        echo "[+] Removing containers..."
        docker rm $containers
    else
        echo "No containers found"
    fi

    echo "[+] Listing images..."
    images=$(docker images -qa)
    echo "[+] images: $images"

    if [ ! -z "$images" ]
    then
        echo "[+] Removing images..."
        docker rmi -f $images
    else
        echo "No images found"
    fi

    echo "[+] Listing volumes..."
    volumes=$(docker volume ls -q)
    echo "[+] volumes: $volumes"

    if [ ! -z "$volumes" ]
    then
        echo "[+] Removing volumes..."
        docker volume rm $volumes
    else
        echo "[+] No volumes found"
    fi

    echo "[+] Listing networks..."
    networks=$(docker network ls -q)
    echo "[+] networks: $networks"

    if [ ! -z "$networks" ]
    then
        echo "[+] Removing networks..."
        docker network rm $networks
    else
        echo "[+] No networks found"
    fi

    echo "[+] These should not output any items:"
    docker ps -a
    docker images -a 
    docker volume ls

    echo "[+] This should only show the default networks:"
    docker network ls
}


if [ $1 = "-clean" ] ; then
    echo "${RED} WARNING THIS WILL DELETE THE ~/Labs folder," 
    echo "remove all containers, and delete command history"
    echo "Are you sure you want to continue?"
    read -p "Continue? [yes/NO] : " continue
    case $continue in
        [Yy]* ) 
        rm -rf ~/Labs
        history -c && history -w
        clean_docker
        ;;
        [Nn]* ) exit;;
        * ) exit;;
    esac
    rm -rf ~/Labs/
fi
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
wget -O ~/Labs/dummy_client.py "https://raw.githubusercontent.com/mainframed/DEFCON31/main/dummy_client.py"
ARCH=$(dpkg --print-architecture)
if [ "$ARCH" = "amd64" ]; then
    wget -O ~/Labs/client "https://github.com/mainframed/DEFCON31/raw/main/client_amd64" 
    docker run -d --name defcon31 -p 127.0.0.1:1234:1234 -p 127.0.0.1:31337:31337 mainframed767/defcon31:amd64
elif [ "$ARCH" = "arm64" ]; then
    wget -O ~/Labs/client "https://github.com/mainframed/DEFCON31/raw/main/client_arm64" 
    docker run -d --name defcon31 -p 127.0.0.1:1234:1234 -p 127.0.0.1:31337:31337 mainframed767/defcon31:arm64
else
    echo "${RED}ERROR ERROR ERROR"
    echo " Talk to the instructor about this error"
    echo "ERROR ERROR ERROR"
fi
echo "${ENDCOLOR}"