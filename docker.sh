#!/bin/bash
docker kill defcon31
docker rm defcon31
docker run -d --name defcon31 -p 127.0.0.1:1234:1234 -p 127.0.0.1:51337:31337 mainframed767/defcon31:amd64 
