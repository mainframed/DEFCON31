DC31 README
===========

Welcome to the DC31 Protocol documentation. This Protocol was developed
to control the ARPS automatic tape system remotely. 

Protocol
--------

The protocol speaks TCP/IP. Every byte in every communication is encrypted by
XORing every byte with 0x31 except for the header and the sequence byte.

A DC31 packet can be broken down as:

- HEADER - One byte, always 0x80
- SEQUENCE - Increases with every back and forth communication 
- DATA - the data being sent

For example, after receving and XORing the packet with 0x31 it may look like:

```
\x80\x05LISTUSERS
```

Handshake
---------

Upon initial connection, for security reasons, to prevent fingerprinting,
a handshake must be responded to with the official key. 

The default handshake is: 

SERVER: MESSWITHTHEBEST
CLIENT: DIELIKETHEREST

That is, the first byte the server sends is \x80\x01MESSWITHTHEBEST xor'd with \x31

Sequence
--------

The second byte is always the sequence byte. This byte must be present and 
correct or the server will end the connection. 

The sequence counter is increased on each communication. For example:


client -> seq 3 HELP
server <- seq 4 prints help
client -> seq 5 VERSION
server <- seq 6 print version

Commands
--------

You control who can issue which commands in the config file. Available commands are:

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

Users
-----

Users can log on with the **LOGON user/password** command. 

UserIDs must follow the following rules:

- UserIDs are thre characters long 
- They must begin with an @
- The next two characters are either a number or a letter

If the username does not exist then ARPS will return `phil is not a valid USER`. If the password is invalid it will return `Invalid PASSWORD`

When a user logs on succesfully they will be presented with the message: "@xx is logged on"

Passwords
---------

Passwords can be any length. When new accounts are created the default 
password is `<short month>@<four number year>`. e.g. mar@1989