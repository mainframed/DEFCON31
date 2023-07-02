# Import socket module
import socket

RESPONSE = b"\xDE\xFC\x04"

def Main():
    # local host IP '127.0.0.1'
    host = '127.0.0.1'
 
    # Define the port on which you want to connect
    port = 1234
    print ("Connecting to:", host,port)
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
 
    # connect to server on local computer
    s.connect((host,port))
    d = s.recv(9046)
    print(d)
    if d == b"\xDE\xFC\x04":
        s.send(b"\xDE\xFC\x04")
        d = s.recv(9046)
        print(d)

 
    s.close()
 
if __name__ == '__main__':
    Main()