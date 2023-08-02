# Lab 3 - Update Nmap Probe file

*Purpose*

In this lab you'll learn how to access and update the probe file


# Open the terminal app in your class VM
# Make sure you're in the `~/Labs` folder: `cd ~/Labs`
# Scan port 1234 with Nmap: `./nmap/nmap localhost -p 1234 -sV -dd -vv` (this will take a while)
# Run the client: `python3 ./dummy_client.py` and notice the output
# Open the dummy client script in VS Code: `code ./dummy_client.py` (read the code and notice the program flow)

Time to make our Probe

# Open the probe file: `code ~/Labs/nmap/nmap-service-probes`
# Go down to line 16657 (this should be above a line that says NEXT PROBE)
# Hit enter twice then paste the following:

```
#############################NEXT PROBE##############################
# First we send our 0xDEFC04
Probe TCP dc31 q|\xde\xfc\x04|
# Set the rarity
rarity 9
# We know the port is 1234
ports 1234
# Matches DEFCON DUMMY PROGRAM V1 Release 2.5 and extracts the version number
match dc31 m|^\xde\xfc\x04DEFCON DUMMY PROGRAM V1 Release (\d+\.\d+)| p/DEFCON 31 Server/
```

# Rerun the port scan: `./nmap/nmap localhost -p 1234 -sV` (notice this takes less time now)

Congrats you just updated the probe file!

*Pro tips*

If you're working on a single port and trying to debug or figure things out, you can move the nmap-service-probes file, replace it with an empty probe file and only put your single probe in there for testing (this will speed up service scans as well)

We're working in the `nmap` folder. If you want to make the changes global, on something like kali, then you'll need to change the nmap probe file that exists in /usr/share/nmap (or similar depending on distro)

# Lab 4 - Simple Probe Script Update

''Purpose'' 

In this lab you'll learn that Nmap scripts can change the results of a probe or augment changes. 

We haven't introduced how the scripts work just yet. 

''Steps''

# In a terminal make sure you're in the `~/Labs` folder
# Create a new script file called `lab4.nse`: `touch lab4.nse`
# Open this file in VS Code (or an editor of your choice): `code lab4.nse`
# Paste the script below:<span>
```lua
local stdnse = require "stdnse"
local shortport = require "shortport"
local nsedebug  = require "nsedebug"

author = "Soldier of Fortran"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"version"}
description = [[Test script for defcon31 class. 
This script replicates the handshake for the class and gathers the proper 
information that the probe file misses.
]]

---
-- @usage
-- nmap --script lab4 <target>
-- @args none
-- @output
-- PORT     STATE SERVICE  VERSION
-- 1234/tcp open  defcon31 DEFCON DUMMY PROGRAM 1.2.5


portrule = function(host, port)
  return port.number == 1234
    and port.state == "open"
    and not(shortport.port_is_excluded(port.number,port.protocol))
end

local DC_PROTOCOLS = {
    "ssl",
    "tcp"
  }

-- Tests for SSL
--
-- @param host host NSE object
-- @param port port NSE object
-- @return true and a socket object on connect, otherwise false and the error
local dc_open = function(host, port)
    for _, proto in pairs(DC_PROTOCOLS) do
      local sock = nmap.new_socket()
      sock:set_timeout(2000)
      local status, err = sock:connect(host, port, proto)
      if status then
        DC_PROTOCOLS = {proto}
        return true, sock
      end
      stdnse.debug(2,"Can't connect using %s: %s", proto, err)
      sock:close()
    end
    return false, err
  end

-- The Action Section --
action = function(host, port)
  -- Send our handshake DE:FC:04
  local defconchars = string.char(0xde,0xfc,0x04)
  local status, sock = dc_open(host, port)
  local replychars = ""
  local version = ""
  -- Check if it failed
  if not status then
    return false, sock
  end

  local status, handshake = sock:receive_bytes(3)
  stdnse.debug("DEFCON 31 Handshake attempt")
  if status == true and handshake == defconchars then
    -- Now we need to reply
    sock:send(defconchars)
    status, replychars = sock:receive_bytes(36)
    -- Looking for something like DEFCON DUMMY PROGRAM VX Release Y.Z
    local i, j = string.find(replychars, "DEFCON DUMMY")
    
    if i == nil then
      stdnse.debug(3, "Not a DEFCON 31 service")
      return false, sock
    else
      stdnse.debug(3, "This is a DEFCON 31 service")
      i,j = string.find(replychars,"DEFCON DUMMY PROGRAM V")
      local x,y = string.find(replychars,"Release ")
      version = string.sub(replychars,j+1,j+1) ..".".. string.sub(replychars,y+1,y+3)
      stdnse.debug(3, "Version:" .. version)
    end
    port.version.name = "defcon31"
    port.version.product = "DEFCON DUMMY PROGRAM"
    port.version.version = version
    nmap.set_port_version(host, port)

  end -- End Handshake
  sock:close()
  return
end
```
</span>
# Save the script
# In the terminal run an nmap scan: `./nmap/nmap -p 1234 localhost -sV` (notice the ouput)
# In the terminal run an nmap scan: `./nmap/nmap -p 1234 localhost --script defcon31`
# In the terminal run an nmap scan: `./nmap/nmap -p 1234 localhost -sV --script defcon31`


# Lab 5 - Lua Scriptin'

# In a terminal make sure you're in the `~/Labs` folder
# Create a new script file called `defcon31.lua`: `touch defcon31.lua`
# Open this file in VS Code (or an editor of your choice): `code defcon31.lua`
# Put the following in your script: `print("Hello DEFCON 31")`
# Save the script and run it in the terminal: `lua defcon31.lua`
# In the script add the following on a new line: `str = "I'm so tired... oops... Welcome to Class!"`
# Using the `string.find` and `string.sub` functions only print the last three words of `str`
# On a new line add the following `arr = {"talk1","talk2","talk3","talk4","talk5","talk6"}`
# Edit the lua script to print the 5th element in the array
# Using a for loop and an ipair iterator print every element in the array except `talk5`

(this last one I'll do for you):

```lua
arr = {"talk1","talk2","talk3","talk4","talk5","talk6"}
for i,talk in ipairs(arr) do
  if talk ~= "talk5" then 
    print(talk)
  end
end
```

# BONUS: Change the loop to print the number in the array instead of the value

# Lab 6 - Hello World in NSE

# In the `~/Labs` folder create a new file called `lab6.nse` and place the following in that file:

```lua
local stdnse = require "stdnse"
prerule = function()
    return true
  end
action = function(host, port)
  stdnse.verbose(1,[[Hello World from verbose]])
  stdnse.debug(1,[[Hello World from debug]])
  return
end
```

# From the terminal (make sure you're in the `~/Labs` folder) run the nmap script: `./nmap/nmap --script lab6 localhost`
# Notice the verbose output, despite you not passing `-v`, any thoughts on why?
# To show the debug message, however, we need to turn on debug: `./nmap/nmap --script lab6 localhost -d`


Bonus

stdnse provides multiple functions, if you're done early try checking some of them out and playing with them. https://nmap.org/nsedoc/lib/stdnse.html


# Labs 7 

# Make sure you're in the `~/Labs` folder
# Make the file `client` executable: `chmod +x client`
# Run the client: `./client`

You should be presented with this screen (if not put your hand up):

```
Connecting to: 127.0.0.1 31337
Handshake successful
ENTERING ARPS 331
     _____   _____   __ __ 
    |     | |_   _| |  |  |
    |  |  |   | |   |  |  |
    |_____|   |_|    \___/ 
                   
       _
      / \
     / _ \    utomated          -----------------------------------------
    / ___ \                     -                                       -
  _/ /   \ \_                   - WARNING WARNING WARNING WARNING WARNI -
 |____|_|____|                  - NG WARNING WARNING WARNING WARNING WA -
   ______                       -                                       -
  |_   __ \                     -                                       -
    | |__) |                    -   This systems is currently:          -
    |  __ /   ecording          -                 ON-AIR                -
   _| |  \ \_                   -                                       -
  |____|_|___|                  -          Make changes to              -
   ______                       -          the Schedule first.          -
  |_   __ \                     -                                       -
    | |__) |  layback           -          Only Use this System         -
    |  ___/                     -          for EMERGENCIES              -
   _| |_                        -                                       -
  |_____|_                      -                                       -
    _____                       -                                       -
  .' ____ \                     - RNING WARNING WARNING WARNING WARNING -
  | (___ \_|                    - WARNING WARNING WARNING WARNING WARN  -
   _.____`.  ystem              -                                       -
  | \____) |                    -----------------------------------------
   \______.'

Enter command (type EXIT to quit):
```

Play around with the client a little, we don't have access but try and log on with the username fake/fake?

Here's also a list of commands you may or may not be able to run without logging in, i suggest you try some:

- **ADDUSER**
- **COMMANDS**
- **DELUSER**
- **HELP**
- **LISTUSERS**
- **LOGON**
- **MOTD**
- **SHELLCMD**
- **VERSION**
- **PLAYING**
- **LISTSHOWS**
- **CHANGESHOW**



# Lab 8 

# Go to https://defcon31.soldieroffortran.org/arps_protocol.pdf or go to the section of the class Wiki that explains the protocol: LINK
# Read the spec and take note of the initial packets sent
# By reading the spec we know the following:
 - Each packet of information starts with 0x80
 - Followed by the sequence number (always starts at 1 it appears)
 - It XORs every byte in the communication by 0x31
 - The first thing it sends is `MESSWITHTHEBEST`

This should be enough to write our null probe. Take a minute to figure it out on your own. 

Otherways we could use to figure this out:

# Using wireshark to read the initial handshake
# Write a simple python script to connect
# Hex dump with ncat

 Dumping the output with ncat
======

# Run ncat on port 31337 with the hexdump argument: `./nmap/ncat/ncat -x output.hex localhost 31337`
# Cat the hexdump: `cat output.hex`
# Update our probe file with this initial handshake, make sure you call the service arps, it will be important for later scripts
# Run nmap and observe the output: `./nmap/nmap -p 31337 -sV localhost`


# If you didn't want to try and solve it on your own (or we're running late)

Add this to line 42 in the file `./nmap/nmap-service-pobes` on line 42:

match arps m|^\x80\x01\x7c\x74\x62\x62\x66\x78\x65\x79\x65\x79\x74\x73\x74\x62\x65| p/Automated Recording Playback System/

# Lab 9 

This lab will use what we've learned so far to update the version info. 

# Make sure you're in the `~/Labs` folder
# copy the lua below and place it in the file `~/Labs/arps-version.nse`

```lua
-- Script to get ARPS version
local stdnse = require "stdnse"
local shortport = require "shortport"

-- Make sure you fill out someport and someservice properly
portrule = shortport.port_or_service(<someport>, "<someservice>")

action = function(host, port)
  -- Add a verbose and debug message here letting users know
  -- The debug/verbose lib is stdnse

  <verbose message>
  <debug message>

  local sock = nmap.new_socket()
  local status, err = sock:connect(host, port, "tcp")
  if not status then
    stdnse.debug("Error connecting")
    return false, err
  end

  status, bytes = sock:receive()
  if not status then return false, bytes end
  
  if bytes == <Initial Handshake> then
    -- Send handshake response
    status, err = sock:send(<send some bytes>)
    if not status then return false, err end

    -- Get the initial screen
    status, bytes = sock:receive()
    if not status then return false, bytes end
    
    -- Send 'VERSION'
    status, err = sock:send(<send some bytes>)
    if not status then return false, err end

    -- Get version info
    status, bytes = sock:receive()
    if not status then return false, bytes end

    -- unXOR the version "1.33.7" 
    local version = string.sub(bytes,16)
    local v = ''
    for i=1, #version do
      local byte = string.byte(version,i)
      local decrypt = byte ~ 0x31
      v = v .. string.char(decrypt)
    end

    -- Setting the port version
    <Set the port version and then tell nmap about it here>
  end

  sock:close()
  return
end
```

# Updating the LUA Script

**Note:** I'm not going to do too much hand holding, try and figure it out first (if you get REALLY stuck take a look at Lab 10 where I share the completed script)

# First replace <verbose> and <debug> with messages that users can use when they run your script. `stdnse.verbose()` and `stdnse.debug()` are the functions

# We know that the protocol sends data and expects data in a certain format, we could use wireshark, tcpdump, reading the spec, to figure it all out. I've done the heavy lifting for you here:

- Initial handshake (in hex): `80017c7462626678657965797473746265`
- Handshake reply: `80027578747d787a7465797463746265`
- Request Version info: `800447544342585e5f`

# We have the handshake in a string, we need to convert it to bytes before we send it (or visa versa if we want to compare). The functions `stdnse.fromhex()` and `stdnse.tohex()` will do that for us. You'll need to use these functions and the hex above. Replacing `<Initial Handshake>` and `<send some bytes>` with `stdnse.tohex("xxx")`/`stdnse.fromhex("xxx")`

# Finally, we can set the version, replacing `<Set the port version and then tell nmap about it here>`. We need to set the `version.port.port` to `v` and we also need to tell nmap about it with `nmap.set_port_version(host, port)`

# After making all these changes we can run our nmap script: `./nmap/nmap --script arps-version -p 31337 -sV localhost`

# Lab 10

Enumerate Commands

The flow of this program is basically the same as the previous lab, except we now loop through each command instead of just the one command (version). 

We're also adding in the ability to pass the script an arument

So take the example from last time:

```lua
-- Script to get ARPS version
local stdnse = require "stdnse"
local shortport = require "shortport"

-- Make sure you fill out someport and someservice properly
portrule = shortport.port_or_service(31337, "arps")

action = function(host, port)
  -- Add a verbose and debug message here letting users know
  -- The debug/verbose lib is stdnse

  stdnse.verbose(1,"Connecting to ARPS service")
  stdnse.debug(1,"Connecting to ARPS service: " .. host.ip .. ":" .. port.number)

  local sock = nmap.new_socket()
  local status, err = sock:connect(host, port, "tcp")
  if not status then
    stdnse.debug("Error connecting")
    return false, err
  end

  status, bytes = sock:receive()
  if not status then return false, bytes end
  
  if bytes == stdnse.fromhex("80017c7462626678657965797473746265") then
    -- Send handshake response
    status, err = sock:send(stdnse.fromhex("80027578747d787a7465797463746265"))
    if not status then return false, err end

    -- Get the initial screen
    status, bytes = sock:receive()
    if not status then return false, bytes end
    
    -- Send 'VERSION'
    status, err = sock:send(stdnse.fromhex("800447544342585e5f"))
    if not status then return false, err end

    -- Get version info
    status, bytes = sock:receive()
    if not status then return false, bytes end

    -- unXOR the version "1.33.7" 
    local version = string.sub(bytes,16)
    local v = ''
    for i=1, #version do
      local byte = string.byte(version,i)
      local decrypt = byte ~ 0x31
      v = v .. string.char(decrypt)
    end

    -- Setting the port version
    port.version.version = v
    nmap.set_port_version(host,port)
  end

  sock:close()
  return
end
```


# Copy the `arps-version.nse` script to `arps-command-enum.nse`: `cp arps-version.nse arps-command-enum.nse`
# Edit `arps-command-enum.nse`: `code arps-command-enum.nse`


First we need to add an array of all the commands:

# In the action section, near the top we need to add the following: `local arps_commands = {"ADDUSER", "COMMANDS", "DELUSER", "HELP", "LISTUSERS", "LOGON", "MOTD", "SHELLCMD", "VERSION", "PLAYING", "LISTSHOWS", "CHANGESHOW"}`
# We also need to get the script args if they exist, so add this after the arps_commands: `local command = stdnse.get_script_args(SCRIPT_NAME .. '.command') or nil`
# We then add a quick check to see if we do one command or all: `if command then arps_commands = {command} end`
# Next we need to add a loop through each command before `local sock = nmap.new_socket()`, this for loop will `end` after `sock:close()`. Add the following: `for i=1, #arps_commands do` (make sure you also add the end).

VS Code tip: You can select a block of code and indent that entire block by pressing tab

Your script should look something like this:

```lua
action = function(host, port)
  -- Add a verbose and debug message here letting users know
  -- The debug/verbose lib is stdnse

  stdnse.verbose(1,"Connecting to ARPS service")
  stdnse.debug(1,"Connecting to ARPS service: " .. host.ip .. ":" .. port.number)
  local arps_commands = {"ADDUSER", "COMMANDS", "DELUSER", "HELP", "LISTUSERS", "LOGON", "MOTD", "SHELLCMD", "VERSION", "PLAYING", "LISTSHOWS", "CHANGESHOW"}
  local command = stdnse.get_script_args(SCRIPT_NAME .. '.command') or nil
  if command then arps_commands = {command} end
  for i=1, #arps_commands do
    local sock = nmap.new_socket()
    ...
  end
```

Next we need to change the `-- Send 'VERSION'` to XOR the command with 0x31, prepend 0x80 and and 0x04 (the sequence) and send it

# Remove the line `status, err = sock:send(stdnse.fromhex("800447544342585e5f"))` and replace it with the following:

```lua
      -- Convert string to string XOR with 0x31
      local v = ''
      for j=1, #arps_commands[j] do
        local byte = string.byte(arps_commands[j],i)
        local encrypt = byte ~ 0x31
        v = v .. encrypt
      end
      status, err = sock:send("\x80\x04"..v)
```

We then need to decode the response from the ARPS server:

# Change the line `local version = string.sub(bytes,16)` to `local version = string.sub(bytes,3)` this skips the header and sequence byte

So far we've got a loop that loops through each command, but now we need to tell nmap about the results. We do this using tables.

# Near the begining of the action section add `local results = stdnse.output_table()` this initializes a table we can use
# We can remove the lines `-- Setting the port version` ,`port.version.version = v`, and `nmap.set_port_version(host,port)` because we don't need them
# Replace the lines you just removed with `results[arps_commands[i]] = v` this assigns the nmap output table with the reply from the ARPS server for each command we send
# Finally at the bottom of the action section, instead of an empty `return`, we need to change it to return our table: `return results`

Having that verbose message there is annoying, we can make users require `-vv` to have it show up

# change the line `stdnse.verbose(1,"Connecting to ARPS service")` to `stdnse.verbose(2,"Connecting to ARPS service")`

After you've made these changes your script should look something like this:

```lua
-- Script to get ARPS version
local stdnse = require "stdnse"
local shortport = require "shortport"

-- Make sure you fill out someport and someservice properly
portrule = shortport.port_or_service(31337, "arps")

action = function(host, port)
  -- Add a verbose and debug message here letting users know
  -- The debug/verbose lib is stdnse

  stdnse.verbose(2,"Connecting to ARPS service")
  stdnse.debug(1,"Connecting to ARPS service: " .. host.ip .. ":" .. port.number)

  local results = stdnse.output_table()
  local arps_commands = {"ADDUSER", "COMMANDS", "DELUSER", "HELP", "LISTUSERS", "LOGON", "MOTD", "SHELLCMD", "VERSION", "PLAYING", "LISTSHOWS", "CHANGESHOW"}
  local command = stdnse.get_script_args(SCRIPT_NAME .. '.command') or nil
  if command then arps_commands = {command} end
  for i=1, #arps_commands do
    local sock = nmap.new_socket()
    local status, err = sock:connect(host, port, "tcp")
    if not status then
      stdnse.debug("Error connecting")
      return false, err
    end

    status, bytes = sock:receive()
    if not status then return false, bytes end
    
    if bytes == stdnse.fromhex("80017c7462626678657965797473746265") then
      -- Send handshake response
      status, err = sock:send(stdnse.fromhex("80027578747d787a7465797463746265"))
      if not status then return false, err end

      -- Get the initial screen
      status, bytes = sock:receive()
      if not status then return false, bytes end

      -- Convert string to string XOR with 0x31
      local v = ''
      for j=1, #arps_commands[i] do
        local byte = string.byte(arps_commands[i],j)
        local encrypt = byte ~ 0x31
        v = v .. string.char(encrypt)
      end
      status, err = sock:send("\x80\x04"..v)
      if not status then return false, err end

      -- Get version info
      status, bytes = sock:receive()
      if not status then return false, bytes end

      -- unXOR the return
      local version = string.sub(bytes,3)
      local v = ''
      for i=1, #version do
        local byte = string.byte(version,i)
        local decrypt = byte ~ 0x31
        v = v .. string.char(decrypt)
      end
      
      results[arps_commands[i]] = v

    end

    sock:close()
  end
  return results
end
```

Run our new nmap script:

# Make sure the script we just wrote is in the `~/Labs` folder
# Make sure you're current working directory is `~/Labs`: `cd ~/Labs`
# Run nmap with our new script: `./nmap/nmap -p 31337 -sV --script arps-command-enum localhost`
# Run the script with only one command: `./nmap/nmap -p 31337 -sV --script arps-command-enum --script-args "arps-command-enum.command=VERSION" localhost`

# Lab 11

Let's create a skeleton library in LUA. You'll need to make sure the libary is in the `nmap/nselib` folder.

# Make sure we're in the `~/Labs` folder: `cd ~/Labs`
# Using VS Code we can create our new library: `code ./nmap/nselib/arps.lua`
# Next we need to add some other libraries and the actual ARPS class:

```lua
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
_ENV = stdnse.module("arps", stdnse.seeall)

ARPS = {
    KEY    = 0x31,
    HEADER = stdnse.fromhex("80"),

    -- This is our new class function
    new = function(self, socket)
        local o = {
         socket = socket or nmap.new_socket(),
         seq = 2,
        }
        setmetatable(o, self)
        self.__index = self
        return o
      end,
}

return _ENV
```

This creates our ARPS objext and gives it some variables we can work with, `KEY`, `HEADER`, `self.socket` and `self.seq`. We would use this in a script like `local arps = arps.ARPS:new()`

Now we need to fill in rest of our library with some skeleton functions

# After `end,` but before `}` copy and paste the following:

```lua
    initiate = function(self, host, port)
    end,

    disconnect = function(self)
    end,

    increment_sequence = function(self)
    end,

    send_data = function(self, data)
    end,

    get_data = function(self)
    end,

    xor = function(self, data)
    end,

    send_command = function(self, command)
    end,

    logon = function(self, username, password)
    end,
```

Time to start populating our functions.

## Initiate and Disconnect

The initiate function just initiates the connection, using the code from the previous lab we can populate this function

Inside the initiate function we place the following:

```lua
    local status, err = sock:connect(host, port, "tcp")
    if not status then
      stdnse.debug("Error connecting")
      return false, err
    end

    status, bytes = sock:receive()
    if not status then return false, bytes end
    
    if bytes == stdnse.fromhex("80017c7462626678657965797473746265") then
      -- Send handshake response
      status, err = sock:send(stdnse.fromhex("80027578747d787a7465797463746265"))
      if not status then return false, err end

      -- Get the initial screen
      status, bytes = sock:receive()
      if not status then return false, bytes end
```

Now we just need to replace `sock:` with `self.socket:` and, close the `if` and return the status + any data we received:


# Replace `sock:` with `self.socket:`
# at the end of this snipet we add `end`
# after the added `end` we add `return status, bytes`

after which that section should now look like: 
```lua
    initiate = function(self, host, port)
      local status, err = self.socket:connect(host, port, "tcp")
      if not status then
        stdnse.debug("Error connecting")
        return false, err
      end

      status, bytes = self.socket:receive()
      if not status then return false, bytes end
      
      if bytes == stdnse.fromhex("80017c7462626678657965797473746265") then
        -- Send handshake response
        status, err = self.socket:send(stdnse.fromhex("80027578747d787a7465797463746265"))
        if not status then return false, err end

        -- Get the initial screen
        status, bytes = self.socket:receive()
        if not status then return false, bytes end
      end
      return status, bytes
    end,
```

And since we're here lets make the disconnect function

# add the following two lines to the disconnect function:

```lua
      if self.socket then self.socket:close() end
      self.seq = 2
      return
```

Finally lets add some comments to make this easier to use

# At the top of the document add the following comments and change your name and date as needed:

```lua
---
-- Library methods for handling ARPS, creating and parsing packets.
--
-- @author <your name>
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
--
-- Summary
-- Implements an ARPS/DC31 object
--
-- <code>
-- local arps = ARPS:new()
-- status, err = arps:initiate(host, port)
-- status, reply = arps:send_command("version")
-- status, reply = arps:logon("version")
-- </code>

-- Created <date> - v0.1
```

For the initiate we should add a comment as well, add this comment right above `initiate = function(self, host, port)`:

```lua
--- Initiate a Connection to a ARPS Server
-- @param host The nmap host passed to the action section
-- @param port The nmap port passed to the action section
-- @return status, bytes/error Returns the results, true or false, and also the bytes received or the error message
```

So now our arps.lua library should look something like this:

```lua
---
-- Library methods for handling ARPS, creating and parsing packets.
--
-- @author <your name>
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
--
-- Summary
-- Implements an ARPS/DC31 object
--
-- <code>
-- local arps = ARPS:new()
-- status, err = arps:initiate(host, port)
-- status, reply = arps:send_command("version")
-- status, reply = arps:logon("version")
-- </code>

-- Created <date> - v0.1

local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
_ENV = stdnse.module("arps", stdnse.seeall)

ARPS = {
    KEY    = 0x31,
    HEADER = stdnse.fromhex("80"),

    -- This is our new class function
    new = function(self, socket)
        local o = {
         socket = socket or nmap.new_socket(),
         seq = 2,
        }
        setmetatable(o, self)
        self.__index = self
        return o
    end,

    --- Initiate a Connection to a ARPS Server
    -- @param host The nmap host passed to the action section
    -- @param port The nmap port passed to the action section
    -- @return status, bytes/error Returns the results, true or false, and also the bytes received or the error message

    initiate = function(self, host, port)
      local status, err = self.socket:connect(host, port, "tcp")
      if not status then
        stdnse.debug("Error connecting")
        return false, err
      end

      status, bytes = self.socket:receive()
      if not status then return false, bytes end
      
      if bytes == stdnse.fromhex("80017c7462626678657965797473746265") then
        -- Send handshake response
        status, err = self.socket:send(stdnse.fromhex("80027578747d787a7465797463746265"))
        if not status then return false, err end

        -- Get the initial screen
        status, bytes = self.socket:receive()
        if not status then return false, bytes end
      end
      return status, bytes
    end,

    disconnect = function(self)
      if self.socket then self.socket:close() end
      self.seq = 2
      return
    end,

    increment_sequence = function(self)
    end,

    send_data = function(self, data)
    end,

    get_data = function(self)
    end,

    xor = function(self, data)

    send_command = function(self, command)
    end,

    logon = function(self, username, password)
    end,
}

return _ENV
```

Now we save the script and we can test it for any syntax issues:

# Save the script in VS Code
# Add the following to `arps-command-enum.nse`: `local arps = require "arps"`
# Run the nmap script: `./nmap/nmap -p 31336 --script arps-command-enum.nse`

Check the output, if you get no errors congrats! If you have errors try solving them yourself then put up your hand. 

# Lab 12

Now we need to fill in the rest of the functions

`increment_sequence`:

this is an easy one, just add `self.seq = self.seq + 2` to the function (between function and end). Why do we use two here?

`xor`:

This is exactly the same as our for loops in the previous scripts, we just need to add a return. 

Add the following to this function:

```lua
local v = ''
for i=1, #data do
  local byte = string.byte(data,i)
  local encrypt = byte ~ self.KEY
  v = v .. string.char(encrypt)
end
return v
```

`send_data`:

For this function we need to:

# encode the data
# increment the sequence byte
# prepend the header and sequence bytes

```lua
-- Encode the data
local d = self:xor(data)

-- Increment sequence
self:increment_sequence()

-- send it
local status, err = self.socket:send(self.HEADER .. string.char(self.seq) .. d)
if not status then
  stdnse.debug("Error Sending data: " .. err)
end
return status
```

`get_data`:

For this function we need to:

# strip the first two bytes
# return the decoded data

We can do in a few lines:

```lua
status, data = self.socket:receive()
if not status then
  stdnse.debug("Error Receiving data: " .. data)
end
return self:xor( string.sub(data,3) )
```

Finally we can build the `send_command`/`logon` functions:

`send_command`:

For this function we need to: 

# Send the command
# return the response

```lua
local status = self:send_data(command)
if not status then
  stdnse.debug("Error sending command: " .. command)
end
return self:get_data()
```

`logon`:

For this function we need to: 

# Send the logon command with the username and password
# return the response

```lua
local status = self:send_data("LOGON ".. username .. "/" .. password)

if not status then
  stdnse.debug("Error with LOGON command: ")
end
return self:get_data()
```


With all these functions complete your library should look something like this:


```lua
---
-- Library methods for handling ARPS, creating and parsing packets.
--
-- @author <your name>
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
--
-- Summary
-- Implements an ARPS/DC31 object
--
-- <code>
-- local arps = ARPS:new()
-- status, err = arps:initiate(host, port)
-- status, reply = arps:send_command("version")
-- status, reply = arps:logon("version")
-- </code>

-- Created <date> - v0.1

local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
_ENV = stdnse.module("arps", stdnse.seeall)

ARPS = {
    KEY    = 0x31,
    HEADER = stdnse.fromhex("80"),

    -- This is our new class function
    new = function(self, socket)
        local o = {
         socket = socket or nmap.new_socket(),
         seq = 2,
        }
        setmetatable(o, self)
        self.__index = self
        return o
    end,

    --- Initiate a Connection to a ARPS Server
    -- @param host The nmap host passed to the action section
    -- @param port The nmap port passed to the action section
    -- @return status, bytes/error Returns the results, true or false, and also the bytes received or the error message

    initiate = function(self, host, port)
      local status, err = self.socket:connect(host, port, "tcp")
      if not status then
        stdnse.debug("Error connecting")
        return false, err
      end

      status, bytes = self.socket:receive()
      if not status then return false, bytes end
      
      if bytes == stdnse.fromhex("80017c7462626678657965797473746265") then
        -- Send handshake response
        status, err = self.socket:send(stdnse.fromhex("80027578747d787a7465797463746265"))
        if not status then return false, err end

        -- Get the initial screen
        status, bytes = self.socket:receive()
        if not status then return false, bytes end
      end
      return status, bytes
    end,

    disconnect = function(self)
      if self.socket then self.socket:close() end

      self.seq = 2
      return
    end,

    increment_sequence = function(self)
      self.seq = self.seq + 2
    end,

    send_data = function(self, data)
      -- Encode the data
      local d = self:xor(data)

      -- Increment sequence
      self:increment_sequence()

      -- send it
      local status, err = self.socket:send(self.HEADER .. string.char(self.seq) .. d)
      if not status then
        stdnse.debug("Error Sending data: " .. err)
      end
      return status
    end,

    get_data = function(self)
      status, data = self.socket:receive()
      if not status then
        stdnse.debug("Error Receiving data: " .. data)
      end
      return self:xor( string.sub(data,3) )
    end,

    xor = function(self, data)
      local v = ''
      for i=1, #data do
        local byte = string.byte(data,i)
        local encrypt = byte ~ self.KEY
        v = v .. string.char(encrypt)
      end
      return v
    end,

    send_command = function(self, command)
      local status = self:send_data(command)
      if not status then
        stdnse.debug("Error sending command: " .. command)
      end
      return self:get_data()
    end,

    logon = function(self, username, password)
      local status = self:send_data("LOGON ".. username .. "/" .. password)
      if not status then
        stdnse.debug("Error with LOGON command: ")
      end
      return self:get_data()
    end,
}

return _ENV
```


# Lab 13

We can now use our library to rewrite the commands enumeration script: `code arps-command-enum.nse`

Before we proceed lets make a backup: `cp arps-command-enum.nse arps-command-enum.old && cp arps-version.nse arps-version.old`

Open that script and replace it with the following:

```lua
-- Script to get ARPS version
local stdnse = require "stdnse"
local shortport = require "shortport"
local arps = require "arps"

-- Make sure you fill out someport and someservice properly
portrule = shortport.port_or_service(31337, "arps")

action = function(host, port)

  stdnse.verbose(1,"Connecting to ARPS service")
  stdnse.debug(1,"Connecting to ARPS service: " .. host.ip .. ":" .. port.number)

  local results = stdnse.output_table()
  local arps_commands = {"ADDUSER", "COMMANDS", "DELUSER", "HELP", "LISTUSERS", "LOGON", "MOTD", "SHELLCMD", "VERSION", "PLAYING", "LISTSHOWS", "CHANGESHOW"}
  local command = stdnse.get_script_args(SCRIPT_NAME .. '.command') or nil
  if command then arps_commands = {command} end
  -- Time to use our new ARPS library
  arps_o = arps.ARPS:new()
  local status, err = arps_o:initiate(host,port)
  for i=1, #arps_commands do
      stdnse.debug(arps_commands[i])
      results[arps_commands[i]] = arps_o:send_command(arps_commands[i])
  end
  arps_o:disconnect()
  return results
end
```

Let's also change the version script: `code arps-version.nse`

```lua
-- Script to get ARPS version
local stdnse = require "stdnse"
local shortport = require "shortport"
local arps = require "arps"

-- Make sure you fill out someport and someservice properly
portrule = shortport.port_or_service(31337, "arps")

action = function(host, port)
  arps_o = arps.ARPS:new()
  local status, err = arps_o:initiate(host,port)
  local version = string.sub(arps_o:send_command("VERSION"),14)
  -- Setting the port version
  port.version.version = version
  nmap.set_port_version(host,port)
  arps_o:disconnect()
  return
end
```

Notice how much shorter these scripts are now. 

# Lab 14

Let's break in to this service!

First we're going to write a script to enumerate all the users then a script to bruteforce all the users

** User Enumeration

With our new library this becomes fairly trivial. What do we need to enumerate the entire user space?

Users are made up of @ + two alphanumeric characters, so we're going to use a LUA iterator

# Create the file `arps-enum.nse` and edit it with VS Code
# Place the following at the top of the file:

```lua
-- Script to enumerate all users
local stdnse = require "stdnse"
local shortport = require "shortport"
<add the arps library here>

portrule = shortport.port_or_service(31337, "arps")
```

Make sure you replace `<add the arps library here>` with the library

Next, for the class I've created an iterator that will loop through every valid user ID type, iterators are a little complex for the class but basically return a value each time the function is called, add this to the script:

```lua
-- User Iterator
user_iter = function ()
    local a = "abcdefghijklmnopqrstuvwxyz0123456789"
    local i = 1
    local j = 0
    return function ()
             if j >= #a then 
              j = 0 
              i = i + 1
            end
             j = j + 1
             if i <= #a then return "@" .. string.sub(a,i,i) .. string.sub(a,j,j) end
           end
  end
```

Finally, create the action section of the script:

```lua
action = function(host, port)

end
```

That's a pretty empty script! You need to fill it in!

First you'll need a new arps object, a results table and a valid users table:

```
local results = stdnse.output_table()
local valid_users = {}
local arps_o = <a new arps object>
local status, err = <arps initiate>
```

make sure you fill in the missing pieces!

With that done we can do our loop

```
for user in <iterator function above> do
  -- Clever students may have realized what happens when the sequence is above 255
  -- We just need to disconnect and reconnect
  if arps_o.seq > 250 then 
    arps_o:disconnect()
    status, err = arps_o:initiate(host,port)
  end
```

next we do our check to see if the user is a valid user or not

```
if arps_o:<logon function with user and a fake password> == "Invalid PASSWORD" then
  table.insert(valid_users,user)
end
```

lastly we tell nmap the results

```
results["Valid Users"] = valid_users
return results
```

With all that done your script should look something like this (if you just skipped ahead here, tsk tsk)

```lua
-- Script to enumerate all users
local stdnse = require "stdnse"
local shortport = require "shortport"
local arps = require "arps"

portrule = shortport.port_or_service(31337, "arps")

-- User Iterator
user_iter = function ()
    local a = "abcdefghijklmnopqrstuvwxyz0123456789"
    local i = 1
    local j = 0
    return function ()
             if j >= #a then 
              j = 0 
              i = i + 1
            end
             j = j + 1
             if i <= #a then return "@" .. string.sub(a,i,i) .. string.sub(a,j,j) end
           end
  end

action = function(host, port)
    local results = stdnse.output_table()
    local valid_users = {}
    arps_o = arps.ARPS:new()
    local status, err = arps_o:initiate(host,port)
    for user in user_iter() do
        if arps_o.seq > 250 then 
            arps_o:disconnect()
            status, err = arps_o:initiate(host,port)
        end
        if arps_o:logon(user,"fake") == "Invalid PASSWORD" then
            table.insert(valid_users,user)
        end
    end
    results["Valid Users"] = valid_users 
    return results
end
```

Now we can run this script and see all the valid users that exist: `./nmap/nmap -p 31337 localhost --script arps-enum`

# Lab 15


# Create the file `arps-brute.nse` and edit it with VS Code
# Place the following at the top of the file:

```
-- Script to bruteforce all users
local stdnse = require "stdnse"
local shortport = require "shortport"
local arps = require "arps"

-- New libraries we need to include
local brute     = require "brute"
local creds     = require "creds"
local unpwdb    = require "unpwdb"

portrule = shortport.port_or_service(31337, "arps")
```

Now we need to make our brute Driver:

For sake of time I've created it for you, just copy and paste the following:

```
-- Brute Driver
Driver = {
    new = function(self, host, port)
        local o = {}
        setmetatable(o, self)
        self.__index = self
        o.host = host
        o.port = port
        -- Here we tell brute to create a new arps object
        o.arps = arps.ARPS:new(brute.new_socket())
        return o
      end,
      connect = function( self )
        -- we then connect with this new object
        local status, err = self.arps:initiate(self.host,self.port)
        if not status then
          stdnse.debug("Could not connect", err )
          return false
        end
        return true
      end,
      disconnect = function( self )
        return self.arps:disconnect()
      end,
      login = function( self, user, pass )
        -- Finally we logon and check the results
        stdnse.verbose(2,"Trying: " .. user .. "/" .. pass)
        if self.arps:logon(user,pass) == user .. " is logged on" then
            return true, creds.Account:new(user, pass, creds.State.VALID)
        end
        return false, brute.Error:new( "login failed" )
      end,
}
```

Then finally the action section:

```
action = function( host, port )
    -- Create new Brute object with the driver
    local engine = brute.Engine:new(Driver, host, port)

    -- set the Brute obtions
    engine.options.script_name = SCRIPT_NAME
    engine.options:setTitle("ARPS Accounts")

    -- Run the brute force
    local status, result = engine:start()

    -- Return the results
    return result
end
```


With all that done your script should look like this:

```lua
-- Script to bruteforce all users
local stdnse = require "stdnse"
local shortport = require "shortport"
local arps = require "arps"

-- New libraries we need to include
local brute     = require "brute"
local creds     = require "creds"
local unpwdb    = require "unpwdb"

portrule = shortport.port_or_service(31337, "arps")

-- Brute Driver
Driver = {
    new = function(self, host, port)
        local o = {}
        setmetatable(o, self)
        self.__index = self
        o.host = host
        o.port = port
        -- Here we tell brute to create a new arps object
        o.arps = arps.ARPS:new(brute.new_socket())
        return o
      end,
      connect = function( self )
        -- we then connect with this new object
        local status, err = self.arps:initiate(self.host,self.port)
        if not status then
          stdnse.debug("Could not connect", err )
          return false
        end
        return true
      end,
      disconnect = function( self )
        return self.arps:disconnect()
      end,
      login = function( self, user, pass )
        -- Finally we logon and check the results
        stdnse.verbose(2,"Trying: " .. user .. "/" .. pass)
        if self.arps:logon(user,pass) == user .. " is logged on" then
            return true, creds.Account:new(user, pass, creds.State.VALID)
        end
        return false, brute.Error:new( "login failed" )
      end,
}

action = function( host, port )
    -- Create new Brute object with the driver
    local engine = brute.Engine:new(Driver, host, port)

    -- set the Brute obtions
    engine.options.script_name = SCRIPT_NAME
    engine.options:setTitle("ARPS Accounts")

    -- Run the brute force
    local status, result = engine:start()

    -- Return the results
    return result
end
```

But we need a list of users!

Run the arps user enum script again: `./nmap/nmap -p 31337 localhost --script arps-enum`

We need to extract just the users and put them in a file. We can do that with a little bash-fu: `./nmap/nmap localhost -p 31337 -sV --script arps-enum |grep "@"|awk '{print $2}' > arps_users.txt`

We also need a password, since we know the default password is month@year we'll try `aug@2023`: `echo 'aug@2023' > pass.txt`

Now we have everything we need to brute force some accounts: `./nmap/nmap --script arps-brute -p 31337 localhost --script-args "userdb=arps_users.txt,passdb=pass.txt" -d`

Note: it will take a bit for the script to run, just leave it be! We've added the `-v` so we can see which account we're on.

How many valid users did you find?

BONUS:

I also have it on good authority that some users may have used a password from this list, see if you can crack some more!

BONUS BONUS:

Now that we have some valid users, can you edit the `arps-command-enum.nse` script to take two arguments, a username and a password, before passing the command to see if we have any admin users?

Some tips:

- You can pass the logon after connecting but before checking the command
- We've already added one argument to that script, adding more should be easy


# HELP


If you had to reboot the VM for any reason the docker container will stop running and you'll need to reset it. To do that you issue the following commands

```
docker rm defcon31 && \
docker run -d --name defcon31 -p 127.0.0.1:1234:1234 -p 127.0.0.1:31337:31337 mainframed767/defcon31:arm64
```




