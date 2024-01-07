---
title: '[FCSC 2019] - 3615 Incident (1/3)'
date: 2023-12-07
lastmod: 2023-12-07
draft: false
authors: ["hashp4"]
description: "Solution to the first challenge in the `3615 Incident` series, published at FCSC 2019."
summary: "Solution to the first challenge in the `3615 Incident` series, published at FCSC 2019."
featuredImage: "feature.png"

tags: ["Forensic", "FCSC 2019", "Volatility", "Ransomware"]

series: [3615 Incident]
series_weight: 1
seriesNavigation: true
hiddenFromHomePage: true

categories: ["Writeup"]
---

## Introduction :pushpin: 

Yet another victim of ransomware. Payment of the ransom is not an option, given the amount requested. We're called in to try and restore the encrypted files. The first part of this challenge requires us to find :

- the **name of the executable file of this ransomware**, 
- its **Process ID** (PID),
- the **SHA1 of the file name** `flag.docx` once encrypted.

The expected response format: `ECSC{ransomware_name.exe:pid:sha1}`.

The `mem.dmp.tar.xz` file is supplied. This is a memory image of the victim's computer. In concrete terms, it corresponds to the contents of volatile memory (in other words, **RAM**) at the time of acquisition, and we'll see that it proves to be an excellent source of information for digital forensics.

## 1. The search for ransomware :mag_right: 

### Volatility3
There are several tools available for analyzing a memory image. For the purposes of this challenge, we'll be using `Volatility3` and `grep` (more useful than it sounds :p). 

[Volatility3](https://github.com/volatilityfoundation/volatility3) is an open-source tool for extracting information from a memory dump on a Windows, MacOS or Linux system via plugins.

Installation is very quick:

```bash
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
pip3 install -r requirements.txt
python3 setup.py build 
python3 setup.py install
```

Now the tool is ready to use. :smile:

### OS Identification

First of all, we need to know which operating system the dump comes from. To do this, we can use `grep` in the first instance, filtering on terms like `Windows`, `Linux version`, and so on.

```bash
┌──(hashp4㉿kali)-[~/Bureau]
└─$ strings mem.dmp | grep "Windows"
[...]
WindowsDirectory
Win32API|System Information Functions|GetWindowsDirectory
Microsoft Windows 10 Famille|C:\Windows|\Device\Harddisk0\Partition3
Microsoft Windows 10 Famille
icrosoft Windows 10 Famille
C:\Windows\system32
C:\Windows
Utilisateur Windows
[...]
Windows Korean (CP 949)
Windows Chinese Traditional (CP 950) or Big-5
Windows Central European (CP 1250)
Windows Cyrillic (CP 1251)
Windows Western European (CP 1252)
Windows Greek (CP 1253)
Windows Turkish (CP 1254)
Windows Hebrew (CP 1255)
Windows Arabic (CP 1256)
Windows Baltic (CP 1257)
Windows Vietnamese (CP 1258)
Windows Johab (CP 1361)
[...]
```

From the result, it would appear that the memory image comes from a `Windows` system. To be sure, we can use the `windows.info` plugin:

*(`-f` is the option for specifying the memory dump path.)*
```bash
┌──(hashp4㉿kali)-[~/Bureau]
└─$ python3 ~/Tools/volatility3/vol.py -f ~/Bureau/mem.dmp windows.info
Volatility 3 Framework 2.5.2
Progress:  100.00               PDB scanning finished                                
Variable        Value

Kernel Base     0xf801f4077000
DTB     0x1ab000
Symbols file:///home/hashp4/Tools/volatility3/volatility3/symbols/windows/ntkrnlmp.pdb/D03C5CF7862E48FE84A06333F1CFA598-1.json.xz
Is64Bit True
IsPAE   False
layer_name      0 WindowsIntel32e
memory_layer    1 WindowsCrashDump64Layer
base_layer      2 FileLayer
KdVersionBlock  0xf801f433bdc0
Major/Minor     15.10586
MachineType     34404
KeNumberProcessors      2
SystemTime      2019-05-08 20:04:11
NtSystemRoot    C:\Windows
NtProductType   NtProductWinNt
NtMajorVersion  10
NtMinorVersion  0
PE MajorOperatingSystemVersion  10
PE MinorOperatingSystemVersion  0
PE Machine      34404
PE TimeDateStamp        Wed Jan 27 04:38:01 2016
```

It would therefore appear that the operating system is :
- a **Windows 10** (field `NtMajorVersion`), 
- 64-bit architecture** (field `Is64Bit` at `true`),
- build **10586** (field `Major/Minor`).

Now that we have this information, we can use the right plugins.

### Analyse des processus

To find the name of the ransomware executable file, we can start by listing the processes currently running, using the `windows.pstree` plugin. It can be used to draw up a tree structure, showing **processes** and **their parent**, their **process identifier** (PID), their **creation date**, and so on.

```bash
┌──(hashp4㉿kali)-[~/Bureau]
└─$ python3 ~/Tools/volatility3/vol.py -f ~/Bureau/mem.dmp windows.pstree
Volatility 3 Framework 2.5.2
Progress:  100.00               PDB scanning finished                                
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime

4       0       System  0xe0000f65a040  136     -       N/A     False   2019-05-08 19:57:03.000000      N/A
* 256   4       smss.exe        0xe00010e4b040  3       -       N/A     False   2019-05-08 19:57:03.000000      N/A

[...]

* 3120  544     userinit.exe    0xe00012034080  0       -       1       False   2019-05-08 19:57:14.000000      2019-05-08 19:57:38.000000 
** 3184 3120    explorer.exe    0xe000116e3080  86      -       1       False   2019-05-08 19:57:14.000000      N/A
*** 5444        3184    notepad.exe     0xe00012268100  1       -       1       False   2019-05-08 20:00:29.000000      N/A
*** 5496        3184    notepad++.exe   0xe0001214e080  0       -       1       True    2019-05-08 20:00:33.000000      2019-05-08 20:00:41.000000 
*** 3080        3184    OneDrive.exe    0xe00012774080  17      -       1       True    2019-05-08 19:57:29.000000      N/A
*** 4040        3184    firefox.exe     0xe000125a7840  59      -       1       True    2019-05-08 19:59:06.000000      N/A
**** 4896       4040    firefox.exe     0xe000125f7840  9       -       1       True    2019-05-08 19:59:07.000000      N/A
**** 4736       4040    firefox.exe     0xe00010385080  20      -       1       True    2019-05-08 19:59:08.000000      N/A
**** 3744       4040    firefox.exe     0xe00010347080  19      -       1       True    2019-05-08 19:59:09.000000      N/A
**** 1360       4040    firefox.exe     0xe00012155200  19      -       1       True    2019-05-08 19:59:42.000000      N/A
**** 3256       4040    firefox.exe     0xe00011196080  22      -       1       True    2019-05-08 19:59:11.000000      N/A
**** 5084       4040    firefox.exe     0xe000127446c0  0       -       1       True    2019-05-08 19:59:33.000000      2019-05-08 20:01:04.000000 
*** 4812        3184    vmtoolsd.exe    0xe00012620080  10      -       1       False   2019-05-08 19:57:27.000000      N/A
*** 5840        3184    MSASCui.exe     0xe00012854840  6       -       1       False   2019-05-08 20:01:01.000000      N/A
*** 5208        3184    assistance.exe  0xe000106bb840  9       -       1       True    2019-05-08 20:00:16.000000      N/A
**** 5224       5208    conhost.exe     0xe00010335080  2       -       1       False   2019-05-08 20:00:16.000000      N/A
*** 5176        3184    notepad++.exe   0xe0001287a840  11      -       1       True    2019-05-08 20:01:49.000000      N/A
*** 5596        3184    DumpIt.exe      0xe0001051c840  6       -       1       False   2019-05-08 20:04:09.000000      N/A
**** 5364       5596    conhost.exe     0xe0001051b080  4       -       1       False   2019-05-08 20:04:09.000000      N/A
```
*(Here, I've deliberately removed most of the results for the sake of readability)*

After analysis, we find several processes that appear legitimate (`firefox.exe`, `notepad.exe`, `OneDrive.exe`, ...). However, one of them looks suspicious. It is `assistance.exe` with PID `5208`.

```bash
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime
*** 5208        3184    assistance.exe  0xe000106bb840  9       -       1       True    2019-05-08 20:00:16.000000      N/A
```

Indeed, this is not a process we usually observe. To get to the bottom of it, let's take a closer look.

### Analysis of the binary `assistance.exe`

To learn more about `assistance.exe`, we first need to extract it from the memory dump. To do this, we can use various methods:
1) Extract it using its `PID`. Simply use the `windows.dumpfiles` plugin with the `--pid <PID>` option.
2) Find the location of the executable on the OS and extract it using the associated virtual address. 

The first method is more common (*and practical*), so we'll use the second. :)

To scan the files in the memory image, we can use the `windows.filescan` plugin. What's more, since we know the name of the executable, we can filter using `grep`.

```bash
┌──(hashp4㉿kali)-[~/Bureau]
└─$ python3 ~/Tools/volatility3/vol.py -f ~/Bureau/mem.dmp windows.filescan | grep "assistance.exe"
0xe00011360090.0\Users\TNKLSAI3TGT7O9\Downloads\assistance.exe  216
0xe00011483b40  \Users\TNKLSAI3TGT7O9\Downloads\assistance.exe  216
0xe000121df450  \Users\TNKLSAI3TGT7O9\Downloads\assistance.exe  216
0xe0001256bde0  \;Z:000000000002acd3\vmware-host\Shared Folders\e\assistance.exe        216
```

We can see that it has several different addresses. We can take one of these. Next, we need to dump the executable. Here, we use the `windows.dumpfiles` plugin. It comes with the `--virtaddr <ADDR>` option, which lets you specify the virtual address you've just found.

```bash
┌──(hashp4㉿kali)-[~/Bureau]
└─$ python3 ~/Tools/volatility3/vol.py -f ~/Bureau/mem.dmp -o /tmp/fcsc/dump windows.dumpfiles --virtaddr 0xe00011483b40
Volatility 3 Framework 2.5.2
Progress:  100.00               PDB scanning finished                                
Cache   FileObject      FileName        Result

DataSectionObject       0xe00011483b40  assistance.exe  file.0xe00011483b40.0xe000121e98b0.DataSectionObject.assistance.exe.dat
ImageSectionObject      0xe00011483b40  assistance.exe  file.0xe00011483b40.0xe0001219c830.ImageSectionObject.assistance.exe.img
```
*(the `-o` option is used to specify the destination directory for the executable)*.

Now that we have the executable, let's quickly check that it's actually one, using the `file` command.

```  bash                       
┌──(hashp4㉿kali)-[~/Bureau]
└─$ file /tmp/fcsc/dump/file.0xe00011483b40.0xe000121e98b0.DataSectionObject.assistance.exe.dat 
[...] PE32 executable (console) Intel 80386 (stripped to external PDB), for MS Windows, 6 sections                 
```

Everything looks good! Now let's check if it's malware. If so, it's probably recognized by [VirusTotal](https://www.virustotal.com/). We can then download the executable.

<img width="652" alt="vt-analysis" src="https://gist.github.com/assets/92587864/cf19a7ba-8be8-405c-86f1-58d22fa9cd8f">

Clearly, this is malware belonging to the ransomware family. Let's delve a little deeper into the analysis by opening it in `PEStudio`. This is a tool for quickly finding **artifacts** (*information of investigative value*) within an executable.

<img width="1028" alt="pestudio-output" src="https://gist.github.com/assets/92587864/3ee40255-cfcb-414b-9210-2e85a148186e">

Browsing the `strings` section, we notice the presence of a Github repo: https://github.com/mauri870/ransomware. It probably contains the ransomware's source code. What a bargain!

At this stage of the challenge, we have 2/3 of the flag: `ECSC{assistance.exe:5208`.

- [X] the **name of this ransomware's executable file**, 
- [X] its **Process ID** (PID),
- [ ] the **SHA1 of the file name** `flag.docx` once encrypted.

Now all we need to do is find the last item in this list. We'll now be able to use the source code now available to us.

## 2. Searching for `flag.docx` 🧭

### Quick source code analysis

To understand how encryption works, we need to analyze the file [ransomware.go](https://github.com/mauri870/ransomware/blob/master/cmd/ransomware/ransomware.go) located in `/cmd/ransomware`. Inside, we find the `encryptFiles()` function which, as its name suggests, is in charge of encrypting files. 

*(As it's quite large, I've shortened it to the interesting part (from line 256 to 268)).

```go
func encryptFiles() {
[...]
// Rename the files after all have been encrypted
	cmd.Logger.Println("Renaming files...")
	for _, file := range FilesToRename.Files {
		// Replace the file name by the base64 equivalent
		newpath := strings.Replace(file.Path, file.Name(), base64.StdEncoding.EncodeToString([]byte(file.Name())), -1)

		cmd.Logger.Printf("Renaming %s to %s\n", file.Path, newpath)
		// Rename the original file to the base64 equivalent
		err := utils.RenameFile(file.Path, newpath+cmd.EncryptionExtension)
		if err != nil {
			cmd.Logger.Println(err)
			continue
		}
[...]
```

We can see that this function renames files after encrypting them. The substitution name is the name of the original file encoded in `base64`, to which is added an extension defined by the attacker in the file [common.go](https://github.com/mauri870/ransomware/blob/master/cmd/common.go#L99) (`line 99`).

```go=
// Extension appended to files after encryption
EncryptionExtension = ".encrypted"
```

### Locating the encrypted file in the memory dump

We now know that the hypothetical name of `flag.docx` after encryption is this one encoded in `base64`. We can obtain the string as follows:

```bash
┌──(hashp4㉿kali)-[~/Bureau]
└─$ echo -n "flag.docx" | base64                                                                           
ZmxhZy5kb2N4
```

We can now search for a file with the name `ZmxhZy5kb2N4` in the memory dump. To do this, we'll use the `windows.filescan` plugin and filter on the filename using `grep`.

```bash
┌──(hashp4㉿kali)-[~/Bureau]
└─$ python3 ~/Tools/volatility3/vol.py -f ~/Bureau/mem.dmp  windows.filescan | grep "ZmxhZy5kb2N4" 
0xe000123988d0.0\ZmxhZy5kb2N4.chiffré   216
```

Indeed, the file does exist. We also notice that the file extension is no longer `.encrypted` but `.chiffré`. All we have to do now is calculate the `SHA1` of the full filename using `sha1sum` :

```bash
┌──(hashp4㉿kali)-[~/Bureau]
└─$ echo -n "ZmxhZy5kb2N4.chiffré" | sha1sum 
c9a12b109a58361ff1381fceccdcdcade3ec595a
```

This gives us the last piece of the flag: `:c9a12b109a58361ff1381fceccdcdcade3ec595a}`, so we can check off the last item in our list.
- [x] the **SHA1 of the file name** `flag.docx` once encrypted.


## 3. Flag 🚩

Our analysis yields the following flag: `ECSC{assistance.exe:5208:c9a12b109a58361ff1381fceccdcdcade3ec595a}`.

This concludes the first part of the `3615 Incident` challenge. I hope this writeup has helped you understand the ins and outs of this challenge. Good luck for the second part! :)


