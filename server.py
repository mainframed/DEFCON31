import socket
import threading
from random import randrange
import subprocess


debug = False
port_num = 32337
INIT = "MESSWITHTHEBEST"
RESPONSE = b'DIELIKETHEREST'

SHOWS = {
    "0063": "America First Episode 1",
    "0064": "America First Episode 2",
    "0065": "America First Episode 3",
    "0066": "America First Episode 4",
    "0067": "America First Episode 5",
    "0067": "America First Episode 6",
    "0068" : "Fishing With Eddie Episode 1",
    "0069" : "Fishing With Eddie Episode 2",
    "0070" : "Fishing With Eddie Episode 3",
    "0071" : "Fishing With Eddie Episode 4",
    "0072" : "Fishing With Eddie Episode 5",
    "0073" : "Fishing With Eddie Episode 6",
    "0074" : "The Outer Limits 104",
    "0075" : "The Outer Limits 105",
    "0076" : "The Outer Limits 106",
    "0077" : "The Outer Limits 107",
    "0078" : "The Outer Limits 108",
    "0079" : "Up Your Garden Seed Pilot",
    "0080" : "My House Mystery",
}

COMMANDS = [
    "ADDUSER",
    "COMMANDS",
    "DELUSER",
    "HELP", 
    "LISTUSERS", 
    "LOGON",
    "MOTD", 
    "SHELLCMD", 
    "VERSION",  
    "PLAYING",
    "LISTSHOWS",
    "CHANGESHOW",
]

COMMANDS_DICT = {
    "ADDUSER"    : "Adds a user, syntax ADDUSER username/password ADMIN. Admin is optional, only append for ADMIN users. ADMIN only." ,
    "COMMANDS"   : "This output",
    "CHANGESHOW" : "Changes the currently playing show",
    "DELUSER"    : "Deletes a user, syntax DELUSER username. ADMIN only.",
    "HELP"       : "A help dialog", 
    "LISTSHOWS"  : "Lists available show tapes",
    "LISTUSERS"  : "Lists all users and if they have ADMIN rights. For ADMIN users passwords are also listed.", 
    "LOGON"      : "Logs on a user, syntax LOGON username/password",
    "MOTD"       : "Prints the message of the day", 
    "PLAYING"    : "Prints currently playing episode",
    "SHELLCMD"   : "Issues a shell command. Syntax e.g. SHELLCMD ls -al", 
    "VERSION"    : "Prints the DC31 Software version",  
}

WART_OLD = '''
     _____                                                        
 __ |__  _|   ______  ____    ______  ____   ____    __  ______  
|  \/  \|  | |   ___||    |  |   ___|/     \|    \  /  ||   ___| 
|     /\   | |   ___||    |_ |   |__ |     ||     \/   ||   ___| 
|____/  \__| |______||______||______|\_____/|__/\__/|__||______| 
    |_____|  

WARNING:  Unauthorized access to this system is forbidden and will be
prosecuted by law. By accessing this system, you agree that your actions
may be monitored if unauthorized usage is suspected.  

For user help use the documentation at defcon31.soldieroffortr
                                                                  
'''

WART= '''ENTERING ARPS 331
     _____   _____   __ __ 
    |     | |_   _| |  |  |
    |  |  |   | |   |  |  |
    |_____|   |_|    \___/ 
                   
       _
      / \\
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
'''

HELP = '''\nWelcome to the ARPS system 2000. This is a modern tape management system for todays fast paced television networks.\n Use the LOGON command to administer the system. For a list of commands type 'COMMANDS'.\n\nTo view the currently playing show type 'PLAYING'\n '''

MOTD = "\nThis machine is ON AIR. \n    Do NOT Touch\n\nToday is August 9th, 2023. This system will be going down for maintenence August 10th, 2023."

rand_default = [randrange(40),randrange(40),randrange(40),randrange(40),randrange(40)]


VERSION = "ARPS Server v1.33.7"
LOGON = WART

class ThreadedServer(object):
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.users = []
        self.passwords = []
        self.admin = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))

        with open('users.txt','r') as users:
            usersfile = users.read().splitlines() 
        
        with open('passwords.txt','r') as passwords:
            p = passwords.read().splitlines() 
        
        count = 0
        for u in usersfile:
            if count in rand_default:
                password = 'aug@2023'
            else:
                password = p[randrange(400)]

            if len(u.split()) > 1:
                self.admin.append(u.split()[0])
                if u.split()[0] == "@kl":
                    password = 'aug@2023'
                string = "{} {}".format(u.split()[0], password)
           #     print("[+] Adding ADMIN user {}/{}".format(u.split()[0], password))
                self.users.append(string)
            else:

                string = "{} {}".format(u,password)
           #     print("[+] Adding user {}/{}".format(u,password))
                self.users.append(string)
            count += 1

    def rexor(self, byte_msg, byte_key=b"\x31"):
        encrypt_byte = b''
        for b in byte_msg:
            encrypt_byte += chr(b ^ ord(byte_key)).encode()
        return encrypt_byte

    def xor(self, byte_msg, byte_key="\x31"):
        encrypt_byte = b''
        for b in byte_msg:
            encrypt_byte += chr(ord(b) ^ ord(byte_key)).encode()
        return encrypt_byte
    
    def deluser(self, username):
        for i in self.users:
            if username == i.split()[0]:
                self.users.remove(i)

    def listen(self):
        self.sock.listen(5)
        while True:
            client, address = self.sock.accept()
            print("[SERVER] Connection from {}".format(address))
            client.settimeout(60)
            threading.Thread(target = self.listenToClient,args = (client,address)).start()

    def is_valid_command(self, cmd):
        if cmd.upper() in COMMANDS:
            return True
        else:
            return False

    def is_admin(self, user):
        if user in self.admin:
            return True
        return False

    def check_user(self, u):
        for i in self.users:
            vu = i.split()[0]
            #self.users is "username password"
            if u == vu:
                return True
        return False
    
    def check_password(self, u, p):
        if debug: print('check_password', u, p)
        for i in self.users:
            vu = i.split()[0]
            vp = i.split()[1]
            #self.users is "username password"
            if (u == vu) and (p == vp):
                return True
        return False
        

    
    def is_user(self, user):
        for u in self.users:
            if user in u:
                return True
        return False

    def listenToClient(self, client, address):
        seq = 1
        rseq = 0
        header = b"\x80"
        currently_playing = "0067"
        size = 1024
        logged_on = False
        handshaked = False
        current_user = False
        args = False
        # Initial sequence send
        client.send(header+seq.to_bytes()+self.xor(INIT))
        seq +=1

        while True:
            try:
                data = client.recv(size)
                if data:
                    args = False
                    data_array = bytearray(data)
                    if debug: print("[DEBUG]", data_array, "from",address)
                    
                    rseq = data_array[1]
                    if seq != rseq:
                        raise Exception('Wrong Sequence, recieved {} exepected {}'.format(rseq,seq), address)
                    else:
                        seq +=1

                    client_input = self.rexor(bytes(data_array[2:]))

                    if debug: print('Received from the client :',seq,client_input)
                    
                    if not handshaked:
                        if client_input != RESPONSE:
                            raise Exception('Invalid Handshake', address)
                        
                        if debug: print('Handshake successful',seq,client_input)

                        handshaked = True
                        client.send(header+seq.to_bytes()+self.xor("Handshake successful\n"+LOGON))
                        seq += 1
                        continue
                    
                    client_input = client_input.decode()
                    if " " in client_input:
                        args = client_input.split(' ',1)[1]
                        client_input = client_input.split()[0]

                    if self.is_valid_command(client_input):
                        if debug: print("Command:",client_input)
                        if debug and args: print("Args:",args)
                        
                        if logged_on:
                            if debug: print("logged_on user:", current_user)
                            if self.is_admin(current_user):
                        
                                if client_input.upper() == "ADDUSER":
                                    if debug: print('[ADMIN] Adding user')
                                    new_admin = False
                                    if not args or "/" not in args:
                                        client.send(header+seq.to_bytes()+self.xor("ADDUSER command requires USERNAME/PASSWORD syntax. To add a new ADMIN user add ADMIN to the end. E.g. ADDUSER DC/DC ADMIN"))
                                        seq +=1
                                        continue
                                    
                                    if len(args.split()) > 1:
                                        new_user = args.split()[0].split("/")[0]
                                        new_passw = args.split()[0].split("/")[1]
                                        if args.split()[1].upper() == 'ADMIN':
                                            new_admin = True
                                    else:
                                        new_user = args.split("/")[0]
                                        new_passw = args.split("/")[1]
                                    
                                    if self.check_user(new_user):
                                        client.send(header+seq.to_bytes()+self.xor("User {} already exists".format(new_user)))
                                        seq +=1
                                        continue

                                    
                                    self.users.append("{} {}".format(new_user,new_passw))
                                    if new_admin:
                                        self.admin.append(new_user)
                                        new_user += " as an ADMIN"
                                    client.send(header+seq.to_bytes()+self.xor("Added new user {}".format(new_user)))
                                    seq +=1
                                    args = False
                                    continue
                                elif client_input.upper() == "DELUSER":
                                    if debug: print('[ADMIN] Deleting user')
                                    if not args:
                                        client.send(header+seq.to_bytes()+self.xor("DELUSER requires a username to delete"))
                                        seq +=1
                                        continue
                                    user = args.split()[0]
                                    if self.check_user(user):
                                        self.deluser(user)
                                        client.send(header+seq.to_bytes()+self.xor("user {} deleted".format(user)))
                                        seq +=1
                                        args = False
                                        continue
                                elif client_input.upper() == "LISTUSERS":
                                    if debug: print('[ADMIN] Listing Users')
                                    users =  '+--------+-----------------+--------+\n'
                                    users += '| User   | Password        | Admin  |\n'
                                    users += '+--------+-----------------+--------+\n'
                                    for i in self.users:
                                        u = i.split()[0]
                                        p = i.split()[1]
                                        a = "No"
                                        if self.is_admin(i.split()[0]):
                                            a = "ADMIN"
                                        users += '| {u:<7}| {p:<16}| {a:<7}|\n'.format(u=u,p=p,a=a)
                                    
                                    users += '+--------+-----------------+--------+\n'
                                    client.send(header+seq.to_bytes()+self.xor(users))
                                    seq +=1
                                    continue
                                elif client_input.upper() == "SHELLCMD":
                                    output = ''
                                    if not args:
                                        client.send(header+seq.to_bytes()+self.xor("SHELLCMD requires an argument"))
                                        seq +=1
                                        continue
                                    try:
                                        output = subprocess.run(args.split(), stdout = subprocess.PIPE, stderr=subprocess.PIPE)
                                        output = output.stdout+output.stderr
                                        client.send(header+seq.to_bytes()+self.rexor(output))
                                        seq +=1
                                        continue
                                    except subprocess.CalledProcessError as e:
                                        output = e.stderr
                                    except FileNotFoundError as e:
                                        output = "Error with '{}'".format(args)
                                    except Exception as e:
                                        output = "Fatal Error running '{}'".format(args)
                                    # try:
                                    #     output = subprocess.check_output(
                                    #         args.split(), stderr=subprocess.STDOUT )
                                    # except Exception as e:
                                    #     output = "error"
                                    client.send(header+seq.to_bytes()+self.xor(output))
                                    seq +=1
                                    continue
                            else:

                                if client_input.upper() == "LISTUSERS":
                                    users =  '+--------+--------+\n'
                                    users += '| User   | Admin  |\n'
                                    users += '+--------+--------+\n'
                                    for i in self.users:
                                        u = i.split()[0]
                                        a = "No"
                                        if self.is_admin(i.split()[0]):
                                            a = "ADMIN"
                                        users += '| {u:<7}| {a:<7}|\n'.format(u=u,a=a)
                                    
                                    users += '+--------+--------+\n'
                                    client.send(header+seq.to_bytes()+self.xor(users))
                                    seq +=1
                                    args = False
                                    continue

                            
                            if client_input.upper() == "COMMANDS":
                                
                                # client.send(header+seq.to_bytes()+self.xor(
                                #     ' '.join(COMMANDS)
                                # ))
                                output = '\n'
                                for cmd in COMMANDS_DICT:
                                    output += " {}: {}\n".format(cmd, COMMANDS_DICT[cmd])
                                client.send(header+seq.to_bytes()+self.xor(output))
                                seq +=1
                                continue
                            elif client_input.upper() == "CHANGESHOW":

                                if not args:
                                    client.send(header+seq.to_bytes()+self.xor("CHANGESHOW requires a show serial"))
                                    seq +=1
                                    continue
                                show_num = args.split()[0]
                                if show_num not in SHOWS:
                                    client.send(header+seq.to_bytes()+self.xor("Show number {} not found".format(show_num)))
                                    seq +=1
                                    continue
                                currently_playing = show_num

                                client.send(header+seq.to_bytes()+self.xor("Show changed to {} - {}".format(show_num,SHOWS[currently_playing])))
                                seq +=1
                                continue


                        # You dont need to be logged in for these
                        if client_input.upper() == "MOTD":
                            client.send(header+seq.to_bytes()+self.xor(MOTD))
                            seq +=1
                            continue
                        elif client_input.upper() == "VERSION":
                            #sending version string
                            client.send(header+seq.to_bytes()+self.xor(VERSION))
                            seq +=1
                            continue
                        elif client_input.upper() == "HELP":
                            client.send(header+seq.to_bytes()+self.xor(HELP))
                            seq +=1
                            continue
                        elif client_input.upper() == "PLAYING":
                            client.send(header+seq.to_bytes()+self.xor("{} - {}".format(currently_playing,SHOWS[currently_playing])))
                            seq +=1
                            continue
                        elif client_input.upper() == "LISTSHOWS":
                            showlist =  '+--------+------------------------------+\n'
                            showlist += '| Serial | Title                        |\n'
                            showlist += '+--------+------------------------------+\n'
                            for i in SHOWS:
                                showlist += '| {i:<7}| {t:<29}|\n'.format(i=i,t=SHOWS[i])
                            showlist += '+--------+------------------------------+\n'
                            client.send(header+seq.to_bytes()+self.xor(showlist))
                            seq +=1
                            continue
                        elif client_input.upper() == "LOGON":
                            if logged_on:
                                client.send(header+seq.to_bytes()+self.xor("You are already logged on as {}".format(current_user)))
                                seq +=1
                                continue
                            
                            if not args or "/" not in args:
                                client.send(header+seq.to_bytes()+self.xor("LOGON command requires USERNAME/PASSWORD syntax"))
                                seq +=1
                                continue

                            # Valid syntax, check the login
                            user = args.split("/")[0]
                            passw = args.split("/")[1]
                            args = False

                            if debug: print("Username: {} Password: {}")
                            if not self.is_user(user):
                                client.send(header+seq.to_bytes()+self.xor("{} is not a valid USER".format(user)))
                                seq +=1
                                continue
                            
                            if not self.check_password(user,passw):
                                client.send(header+seq.to_bytes()+self.xor("Invalid PASSWORD"))
                                seq +=1
                                continue

                            client.send(header+seq.to_bytes()+self.xor("{} is logged on".format(user)))
                            seq +=1
                            

                            logged_on = True
                            current_user = user

                            print("[+] user {} is logged on".format(current_user))
                            continue
                        
                        else:
                            if logged_on:
                                client.send(header+seq.to_bytes()+self.xor("Command {} requires ADMIN access".format(client_input)))
                                seq +=1
                                continue
                            else:
                                client.send(header+seq.to_bytes()+self.xor("Command {} requires LOGON".format(client_input)))
                                seq +=1
                                continue

                    else:
                        client.send(header+seq.to_bytes()+self.xor("Invalid Command"))
                        seq +=1
                        continue
                else:
                    raise Exception('Client disconnected', address)
            except Exception as e:
                client.close()
                print('Closing::', e)
                seq = 1
                return False

if __name__ == "__main__":
    
    print("[SERVER] [+] Starting Cool DEFCON31 Example Server")
    #print("[+] Rand Range", rand_default)
    ThreadedServer('0.0.0.0',port_num).listen()