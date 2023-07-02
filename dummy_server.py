#!/usr/bin/env python3
import socket
import threading

PORT = 1234
VERSION = "DEFCON DUMMY PROGRAM V1 Release 2.5"

class ThreadedServer(object):
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))

    def listen(self):
        self.sock.listen(5)
        while True:
            client, address = self.sock.accept()
            client.settimeout(60)
            threading.Thread(target = self.listenToClient,args = (client,address)).start()

    def listenToClient(self, client, address):
        print("[DUMMY] Connection from", address)
        data = False
        size = 1024
        while True:
            try:
                print("[DUMMY] Connection from", address)
                client.send(b"\xDE\xFC\x04")
                data = client.recv(size)
                print(data)
                if data:
                    if data == b"\xDE\xFC\x04":
                        client.send(VERSION.encode())
                    else:
                        client.send(b'\x00')
                else:
                    raise Exception('[DUMMY] Client disconnected')
            except Exception as e:
                data = False
                print(e)
                client.close()
                return False

if __name__ == "__main__":
    print("[DUMMY] Bringing up dummy server")
    ThreadedServer('0.0.0.0',PORT).listen()