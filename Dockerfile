FROM python:3.11-bullseye
RUN unset LD_LIBRARY_PATH && apt-get update && apt-get install --no-install-recommends -yq nodejs npm &&\
    npm install -g tiddlywiki@5.3.0
# For tiddlywiki
COPY wiki/users.txt /auth/users.txt
WORKDIR /var/lib/tiddlywiki
COPY wiki/ /var/lib/tiddlywiki/mywiki
# Add init-and-run script
ADD wiki/start_tiddlywiki.sh /usr/local/bin/start_tiddlywiki
WORKDIR /servers
COPY dummy_server.py server.py spawn.sh passwords.txt users.txt /servers/
#EXPOSE [31337, 1234]
CMD '/servers/spawn.sh'