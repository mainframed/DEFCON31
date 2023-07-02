FROM python:3.11-bullseye
WORKDIR /servers
COPY * /servers/
#EXPOSE [31337, 1234]
CMD '/servers/spawn.sh'