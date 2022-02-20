# ⚙ Practical

Useful commands to get started

## <mark style="color:blue;">Working with ports and services</mark>

*   <mark style="color:yellow;">**netcat**</mark> <mark style="color:yellow;"></mark><mark style="color:yellow;"></mark> : Command used for interacting with TCP/UDP ports.

    Connecting to shells \
    Connect to any listening port and interact with the service running on that port

    **netcat** 10.10.10.10 22      : Helps identify what service is running on a particular port while         showing the version etc... This is called Banner grabbing

    **nc** -nv 10.129.42.253 21 : The nc command is the short way of netcat and here we are saying to output the version of the running service  &#x20;
*   <mark style="color:yellow;">**nmap**</mark>** :** Used for scanning ports&#x20;

    **nmap** 10.126.10.10          : Will show us all available ports or open ports on this web server

    The state can have a value of 'filtered' which means that the firewall only accept specific IPs

    By default, this command only show TCP ports.

    **nmap** -sV -sC -p- 10.129.42.253      : The -sV to perform a version scan, -sC to get more info and -p- to scan all 65 535 ports

    The -sC parameter run by default some useful scripts, but we can run specific scripts :&#x20;

    **nmap** --script \<script name> -p\<port> \<host>
*   <mark style="color:yellow;">**ftp**</mark>** :**&#x20;

    **ftp** -p 10.129.42.253 : So here we connected to the service using ftp.&#x20;
*   <mark style="color:yellow;">**smb**</mark>** :** Used by windows for sharing files (Allows users and admins to share folders and make them accessible remotely by other users.

    **nmap** --script smb-os-discovery.nse -p445 10.10.10.40 : So here we used a specific script to interact with smb and get the OS version.

    **smbclient  -**N -L \\\\\\\10.129.42.15 : The smbclient can interact with smb shares. The -N supresses the password promt and the -L lists for us the available shares on remote host.

    **smbclient -**U bob \\\\\\\10.129.42.15\\\users : The -U means user so here we are trying to log in as the user bob so he will demand password and after that we can do ls for example and access different files etc...

    When connected to the client with SMB, can we use commands like cd to get into a directory and get command if we want to see the contents of a file...
*   <mark style="color:yellow;">**snmp**</mark>** :** Interacts with different equipments

    **snmpwalk** -v 2c -c public 10.129.42.253 1.3.6.1.2.1.1.5.0

## <mark style="color:blue;">Expanding the terminal</mark>                             &#x20;

* <mark style="color:yellow;">**tmux**</mark>** :** Can exapnd the terminal for example put 2 windows next to each other in one terminal. The default key to enter tmux commands is Ctrl+B

## <mark style="color:blue;">Web enumeration</mark>

*   <mark style="color:yellow;">**gobuster**</mark> dir -u http://10.10.10.121/ -w /usr/share/dirb/wordlists/common.txt   : gobuster is a tool  that performs directory enumeration and let us check if we can uncover any hidden files or directories on the webserver that are not intended for public access. So gobuster let us do directory brute-forcing. Here, we run a simple scan using the dirb common.txt wordlist. There also may be essential resources hosted on subdomains, such as admin panels or applications with additional functionality that could be exploited. We can use `GoBuster` to enumerate available subdomains of a given domain using the `dns` flag to specify DNS mode.

    **gobuster** dns -d inlanefreight.com -w /usr/share/SecLists/Discovery/DNS/namelist.txt  : Here we are targeting the domain 'inlanefreight.com'. The scan below reveals several interesting subdomains that we could examine further

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
