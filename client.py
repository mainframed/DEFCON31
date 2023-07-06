# Import socket module
import socket
import sys

RESPONSE = "DIELIKETHEREST"
HEADER = b"\x80"

def rexor(byte_msg, byte_key=b"\x31"):
    encrypt_byte = b''
    for b in byte_msg:
        encrypt_byte += chr(b ^ ord(byte_key)).encode()
    return encrypt_byte

def xor(byte_msg, byte_key="\x31"):
    encrypt_byte = b''
    for b in byte_msg:
        encrypt_byte += chr(ord(b) ^ ord(byte_key)).encode()
    return encrypt_byte
 
def Main():
    # local host IP '127.0.0.1'
    host = '127.0.0.1'
 
    # Define the port on which you want to connect
    port = 31337

    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    
    print ("Connecting to:", host,port)
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
 
    # connect to server on local computer
    s.connect((host,port))
    d = bytearray(s.recv(9046))
    # print the received message
    # here it would be a reverse of sent message
    seq = d[1]
   # print('Received from the server :',seq,rexor(bytes(d[2:])))
   # print("Sending", RESPONSE)
    seq += 1
    s.send(HEADER+seq.to_bytes(length=1, byteorder='big')+xor(RESPONSE))
    d = bytearray(s.recv(9046))
    seq = d[1]
    re = rexor(bytes(d[2:]))
    print(re.decode())
    # We're connected at this point

    while True:
        send_input = input("Enter command (type EXIT to quit): ")
        if send_input.upper() == "EXIT":
            print("Disconnecting")
            sys.exit(0)
        seq += 1
        s.send(HEADER+seq.to_bytes(length=1, byteorder='big')+xor(send_input))
        d = bytearray(s.recv(9046))
        seq = d[1]
        re = rexor(bytes(d[2:]))
        print(re.decode())
 
    s.close()
 
if __name__ == '__main__':
    Main()