FROM python:3.11-bullseye
WORKDIR /servers
COPY dummy_server.py server.py spawn.sh passwords.txt users.txt /servers/
#EXPOSE [31337, 1234]
CMD '/servers/spawn.sh'