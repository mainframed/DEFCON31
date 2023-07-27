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

*Purpose* 

In this lab you'll learn that Nmap scripts can change the results of a probe or augment changes. 

We haven't introduced how the scripts work just yet. 

*Steps*

# In a terminal make sure you're in the `~/Labs` folder
# Create a new script file called `lab4.nse`: `touch lab4.nse`
# Open this file in VS Code (or an editor of your choice): `code lab4.nse`
# Paste the script below:

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
