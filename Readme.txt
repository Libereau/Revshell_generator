Script written in python3.

To make it easier, chmod +x the script, then add it to your bashrc or other in alias : 
- alias revshell="/my/directory/./shell_generator.py"

Before running it, you might need to download the php reverse of pentestmonkey (where you want) and modify the path in the script.

Then call it with all the required args : 
- -i or --ip-local : specify the local ip you want the server to connect to
- -p or --port-local : specify the local port you want the server to connect to
- -s or --shell : spectify the type of reverse shell you want to generate

The script will echo in the terminal the rev shell, or will generate a php file where you called the script. 

![alt text](https://github.com/Libereau/Revshell_generator/blob/main/capture_revshell.png)

It is based on the ressources of : 
- https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php
- https://www.asafety.fr/reverse-shell-one-liner-cheat-sheet/
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md

 
