---
title: '[FCSC 2019] - 3615 Incident (1/3)'
date: 2023-12-07
lastmod: 2023-12-07
draft: false
authors: ["hashp4"]
description: "Solution du premier challenge de la série `3615 Incident` paru lors du FCSC 2019."
summary: "Solution du **premier** challenge de la série `3615 Incident` paru lors du FCSC 2019."
featuredImage: "feature.png"

tags: ["Forensic", "FCSC 2019", "Volatility", "Ransomware"]

series: [3615 Incident]
series_weight: 1
seriesNavigation: true

categories: ["Writeup"]
---

## Introduction :pushpin: 

Une victime de plus tombée sous le coup d’un rançongiciel. Le paiement de la rançon n’est pas envisagée vu le montant demandé. Nous sommes appelés pour essayer de restaurer les fichiers chiffrés. La première partie de ce challenge requiert de trouver :

- le **nom du fichier exécutable de ce rançongiciel**, 
- son **identifiant de processus** (PID),
- le **SHA1 du nom du fichier** `flag.docx` une fois chiffré.

La réponse attendue au format : `ECSC{nom_du_rançongiciel.exe:pid:sha1}`.

Le fichier `mem.dmp.tar.xz` nous est fourni. Il s'agit d'une image mémoire de l'ordinateur de la victime. Concrètement, celle-ci correspond au contenu de la mémoire volatile (autrement dit la **RAM**) au moment de l'acquisition et nous allons voir que cela se révèle être une excellente source d'informations pour de l'investigation numérique. 

## 1. À la recherche du rançongiciel :mag_right: 

### Volatility3
Pour analyser une image mémoire, plusieurs outils s'offrent à nous. Dans le cadre de ce challenge, nous utiliserons `Volatility3` et `grep` (plus utile qu'il n'y paraît :p). 

[Volatility3](https://github.com/volatilityfoundation/volatility3) est un outil open-source permettant d'extraire des informations d'un dump mémoire en provenance d'un système sous Windows, MacOS ou Linux par le biais de plugins.

L'installation est très rapide : 


```bash
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
pip3 install -r requirements.txt
python3 setup.py build 
python3 setup.py install
```

Et voilà, l'outil est prêt à être utilisé. :smile: 

### Identification du système d'exploitation

En premier lieu, il est nécessaire de connaître de quel système d'exploitation provient le dump. Pour ce faire, nous pouvons utiliser `grep` dans un premier temps en filtrant sur des termes comme `Windows`, `Linux version`, etc.

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

Compte-tenu du résultat, il semblerait que l'image mémoire provienne d'un système sous `Windows`. Pour s'en assurer, nous pouvons utiliser le plugin `windows.info` :

*(`-f` est l'option permetant de spécifier le chemin du dump mémoire.)*
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

Il semblerait donc que le système d'exploitation soit :
- un **Windows 10** (champ `NtMajorVersion`), 
- architecture **64 bits** (champ `Is64Bit` à `true`),
- build **10586** (champ `Major/Minor`).

Maintenant que nous détenons ces informations, nous allons pouvoir utiliser les bons plugins. 

### Analyse des processus

Pour pouvoir trouver le nom du fichier exécutable du rançongiciel, nous pouvons commencer par lister les processus en cours d'exécution à l'aide du plugin `windows.pstree`. Il permet d'en dresser une arborescence, montrant **les processus** et **leur parent**, leur **identifiant de processus** (PID), leur **date de création**, etc.

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
*(Ici, j'ai volontairement enlevé la plupart des résultats à des fins de lisibilité)*

Après analyse, nous constatons plusieurs processus qui semblent légitimes (`firefox.exe`, `notepad.exe`, `OneDrive.exe`, ...). Cependant, l'un d'entre eux semble suspect. Il s'agit d'`assistance.exe` ayant pour PID `5208`.

```bash
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime
*** 5208        3184    assistance.exe  0xe000106bb840  9       -       1       True    2019-05-08 20:00:16.000000      N/A
```

En effet, ce n'est pas un processus que nous observons habituellement. Pour en avoir le coeur net, analysons-le plus en profondeur.

### Analyse de l'exécutable `assistance.exe`

Afin d'en apprendre plus sur `assistance.exe`, nous devons d'abord l'extraire du dump mémoire. Pour ce faire, nous pouvons utiliser différentes méthodes :
1) L'extraire à l'aide de son `PID`. Il suffit ensuite d'utiliser le plugin `windows.dumpfiles` avec l'option `--pid <PID>`.
2) Trouver l'emplacement de l'exécutable sur l'OS et l'extraire par le biais de l'adresse virtuelle associée. 

La première méthode étant plus commune (*et pratique*), nous allons donc utiliser la deuxième. :)

Pour scanner les fichiers de l'image mémoire, nous pouvons utiliser le plugin `windows.filescan`. De plus, comme nous connaissons le nom de l'exécutable, nous pouvons filtrer à l'aide de `grep`.

```bash
┌──(hashp4㉿kali)-[~/Bureau]
└─$ python3 ~/Tools/volatility3/vol.py -f ~/Bureau/mem.dmp windows.filescan | grep "assistance.exe"
0xe00011360090.0\Users\TNKLSAI3TGT7O9\Downloads\assistance.exe  216
0xe00011483b40  \Users\TNKLSAI3TGT7O9\Downloads\assistance.exe  216
0xe000121df450  \Users\TNKLSAI3TGT7O9\Downloads\assistance.exe  216
0xe0001256bde0  \;Z:000000000002acd3\vmware-host\Shared Folders\e\assistance.exe        216
```

Nous constatons qu'il possède plusieurs adresses différentes. Nous pouvons prendre l'une de celles-ci. Ensuite, nous devons dump l'exécutable. Ici, c'est le plugin `windows.dumpfiles` que nous utilisons. Il est accompagné de l'option `--virtaddr <ADDR>` qui permet de spécifier l'adresse virtuelle précécemment trouvée. 

```bash
┌──(hashp4㉿kali)-[~/Bureau]
└─$ python3 ~/Tools/volatility3/vol.py -f ~/Bureau/mem.dmp -o /tmp/fcsc/dump windows.dumpfiles --virtaddr 0xe00011483b40
Volatility 3 Framework 2.5.2
Progress:  100.00               PDB scanning finished                                
Cache   FileObject      FileName        Result

DataSectionObject       0xe00011483b40  assistance.exe  file.0xe00011483b40.0xe000121e98b0.DataSectionObject.assistance.exe.dat
ImageSectionObject      0xe00011483b40  assistance.exe  file.0xe00011483b40.0xe0001219c830.ImageSectionObject.assistance.exe.img
```
*(l'option `-o` permet de spécifier le répertoire de destination pour l'exécutable)*

Maintenant que nous disposons de l'exécutable, vérifions rapidement qu'il en soit bien un à l'aide de la commande `file`. 

```  bash                       
┌──(hashp4㉿kali)-[~/Bureau]
└─$ file /tmp/fcsc/dump/file.0xe00011483b40.0xe000121e98b0.DataSectionObject.assistance.exe.dat 
[...] PE32 executable (console) Intel 80386 (stripped to external PDB), for MS Windows, 6 sections                 
```

Tout semble correct ! A présent, vérifions si c'est malware. Si tel est le cas, il est probable qu'il soit reconnu par [VirusTotal](https://www.virustotal.com/). Nous pouvons donc y télécharger l'exécutable.

<img width="652" alt="vt-analysis" src="https://gist.github.com/assets/92587864/cf19a7ba-8be8-405c-86f1-58d22fa9cd8f">

Visiblement, il s'agirait bien d'un malware appartenant à la famille des rançongiciels. Approfondissons légèrement l'analyse en l'ouvrant dans `PEStudio`. C'est un outil qui permet de rapidement trouver des **artifacts** (*informations de valeur pour l'investigation*) au sein d'un exécutable.

<img width="1028" alt="pestudio-output" src="https://gist.github.com/assets/92587864/3ee40255-cfcb-414b-9210-2e85a148186e">

En naviguant dans la section `strings`, nous remarquons la présence d'un repo Github : https://github.com/mauri870/ransomware. Il contient vraisemblablement le code source du rançongiciel. Quelle aubaine !

À ce stade du challenge, nous avons donc les 2/3 du flag : `ECSC{assistance.exe:5208`.

- [X] le **nom du fichier exécutable de ce rançongiciel**, 
- [X] son **identifiant de processus** (PID),
- [ ] le **SHA1 du nom du fichier** `flag.docx` une fois chiffré.

Il ne manque plus qu'à trouver le dernier élément de cette liste. Nous allons pouvoir utiliser le code source qui est à présent à notre disposition.

## 2. Recherche de `flag.docx` 🧭

### Rapide analyse du code source

Pour comprendre comment le chiffrement fonctionne, nous devons analyser le fichier [ransomware.go](https://github.com/mauri870/ransomware/blob/master/cmd/ransomware/ransomware.go) situé dans `/cmd/ransomware`. À l'intérieur, nous retrouvons la fonction `encryptFiles()` qui, comme son nom l'indique, est en charge du chiffrement des fichiers. 

*(Celle-ci étant de taille conséquente, je l'ai raccourci à la partie intéressante (de la ligne 256 à 268)).*

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

Nous pouvons constater que cette fonction renomme les fichiers après les avoir chiffrés. Le nom de substitution est le nom du fichier original encodé en `base64` auquel on y ajoute une extension définie par l'attaquant dans le fichier [common.go](https://github.com/mauri870/ransomware/blob/master/cmd/common.go#L99) (`ligne 99`). 

```go=
// Extension appended to files after encryption
EncryptionExtension = ".encrypted"
```

### Localisation du fichier chiffré dans le dump mémoire

Nous savons à présent que le nom hypothétique de `flag.docx` après chiffrement est celui-ci encodé en `base64`. Nous pouvons obtenir la chaîne de caractère de la manière suivante :

```bash
┌──(hashp4㉿kali)-[~/Bureau]
└─$ echo -n "flag.docx" | base64                                                                           
ZmxhZy5kb2N4
```

Nous pouvons désormais chercher s'il existe un fichier ayant le nom `ZmxhZy5kb2N4` dans le dump mémoire. Pour ce faire, nous allons utiliser le plugin `windows.filescan` et filtrant sur le nom de fichier à l'aide de `grep`.

```bash
┌──(hashp4㉿kali)-[~/Bureau]
└─$ python3 ~/Tools/volatility3/vol.py -f ~/Bureau/mem.dmp  windows.filescan | grep "ZmxhZy5kb2N4" 
0xe000123988d0.0\ZmxhZy5kb2N4.chiffré   216
```

Effectivement, le fichier existe bel et bien. Par ailleurs, nous remarquons que l'extension de fichier n'est plus `.encrypted` mais `.chiffré`. Nous n'avons plus qu'à calculer le `SHA1` du nom de fichier complet à l'aide de `sha1sum` :

```bash
┌──(hashp4㉿kali)-[~/Bureau]
└─$ echo -n "ZmxhZy5kb2N4.chiffré" | sha1sum 
c9a12b109a58361ff1381fceccdcdcade3ec595a
```

Nous obtenons ainsi le dernier morceau du flag : `:c9a12b109a58361ff1381fceccdcdcade3ec595a}` et pouvons ainsi cocher le dernier élément de notre liste.
- [x] le **SHA1 du nom du fichier** `flag.docx` une fois chiffré.


## 3. Flag 🚩

Grâce à notre analyse, nous obtenons le flag suivant : `ECSC{assistance.exe:5208:c9a12b109a58361ff1381fceccdcdcade3ec595a}`

Cela marque la conclusion de cette première partie du challenge `3615 Incident`. J'espère que ce writeup vous aura permis de comprendre les tenants et les aboutissants de cette épreuve. Bon courage pour la deuxième partie ! :)


