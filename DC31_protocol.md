DC31 README
===========

Welcome to the DC31 Protocol documentation. This Protocol was developed
to control the ARPS automatic tape system. 

Protocol
--------

The protocol speaks TCP/IP. Every byte in every communication is encrypted by
XORing every byte with 0x31.

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

Upon initial connection, for security reasons to prevent fingerprinting
a handshake must be responded to with the official key. 

The default handshake is: 

SERVER: MESSWITHTHEBEST
CLIENT: DIELIKETHEREST

Sequence
--------

The second byte is always the sequence byte. This byte must be present and 
correct or the server will end the connection. 

The sequence counter is increased on each communication. For example:


client -> seq 3 HELP
server <- seq 4 prints help
client -> seq 5 VERSION
server <- seq 6 print version