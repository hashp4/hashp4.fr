# [FCSC 2019] - 3615 Incident (2/3)


## Introduction :pushpin:

Le contexte reste le même que lors de la première partie. Une victime de plus est tombée sous le coup d’un rançongiciel. Le paiement de la rançon n’est pas envisagée vu le montant demandé. Nous sommes donc appelés pour essayer de restaurer les fichiers chiffrés.

Cette fois-ci, l'objectif est de **retrouver la clé de chiffrement de ce rançongiciel** !

Note : Réponse attendue au format `ECSC{hey.hex()}`.

(La résolution de l'épreuve s'effectue toujours à l'aide du fichier `mem.dmp.tar.xz`. Pour rappel, il s'agit d'une image mémoire de l'ordinateur de la victime. Concrètement, celle-ci correspond au contenu de la mémoire volatile (`RAM`) au moment de l'acquisition et nous allons voir que cela se révèle être une excellente source d'informations pour de l'investigation numérique. 

## 1. Analyse du code source du rançongiciel 🔬

Suite à notre analyse lors de la première partie, nous avons la chance de disposer du code source de ce rançongiciel. Pour rappel, il se trouve ici : https://github.com/mauri870/ransomware. Et heureusement, car nous n'avions pas tellement envie de reverse du Go, n'est-ce pas ? :D 

### Un zoom sur `ransomware.go`

Commençons par trouver la manière dont la clé est générée. La fonction `encryptFile()` dans le fichier [cmd/ransomware/ransomware.go, à la ligne 112](https://github.com/mauri870/ransomware/blob/master/cmd/ransomware/ransomware.go#L112) nous permet d'en apprendre un peu plus.

```go
func encryptFiles() {
	keys := make(map[string]string)
	[...]
		// Generate the id and encryption key
		keys["id"], _ = utils.GenerateRandomANString(32)
		keys["enckey"], _ = utils.GenerateRandomANString(32)

		// Persist the key pair on server
		res, err := Client.AddNewKeyPair(keys["id"], keys["enckey"])
	[...]
```

Nous constatons 2 choses : 
- La génération d'un `id` à l'aide de la fonction `GenerateRandomANString()` située dans le fichier `utils` et ayant pour paramètre `32`.
- La génération de `enckey` à l'aide de la fonction `GenerateRandomANString()` située dans le fichier `utils` et ayant pour paramètre `32`.

Ensuite, ce couple `id` et `enckey` est envoyé sur un serveur à l'aide de la fonction `AddNewKeyPair()` située dans le fichier `client`.

Nous pouvons supposer que l'`id` et la clé de chiffrement `enckey` (*qui est sûrement le diminutif de `encrypted key`*) sont tout deux une chaîne de 32 caractères générés aléatoirement. Pour en être sûr, nous pouvons étudier la fonction correspondante.

### Un zoom sur `utils.go`

Ici, ce qui nous intéresse c'est la fonction `GenerateRandomANString()`, [à la ligne 13 de utils/utils.go](https://github.com/mauri870/ransomware/blob/master/utils/utils.go#L13). 

```go
// Generate a random alphanumeric string with the given size
func GenerateRandomANString(size int) (string, error) {
	key := make([]byte, size)
	_, err := rand.Read(key)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(key)[:size], nil
}
```

La fonction est plutôt simple. Elle prend un entier en paramètre et génère une chaîne de caractère aléatoire de la même taille. Celle-ci est ensuite encodée en hexadécimal à l'aide de la fonction `hex.EncodeToString()` avant d'être retournée. 

Notre hypothèse est donc confirmée. Nous sommes bien à la recherche d'une chaîne de 32 caractères et nous savons qu'ils sont hexadécimaux. Mais nous n'avons encore aucune piste sur le moyen de récupérer cette fameuse clé...


### Un zoom sur `client.go`

Regardons de plus près la fonction `AddNewKeyPair()` [dans client/client.go, ligne 90](https://github.com/mauri870/ransomware/blob/master/client/client.go#L90).

```go
// AddNewKeyPair persist a new keypair on server
func (c *Client) AddNewKeyPair(id, encKey string) (*http.Response, error) {
	payload := fmt.Sprintf(`{"id": "%s", "enckey": "%s"}`, id, encKey)
	return c.SendEncryptedPayload("/api/keys/add", payload, map[string]string{})
}
```

Cette fonction prends bien en paramètre un `id` et une clé de chiffrement `enckey`. Elle va ensuite mettre en forme la charge utile (*payload* en anglais) sous la forme : 

```json
{
    "id": "l'id associé",
    "enckey": "la clé de chiffrement"
}
```

Puis, il sera chiffré et envoyé au serveur de l'attaquant par le biais d'une API à travers l'URI `/api/key/add` via la fonction `SendEncryptedPayload()` *(je vous laisse le soin d'aller regarder cette fonction plus en détail si cela vous intéresse)*. Il est donc intéressant de se concentrer sur l'envoi de cette charge utile pour retrouver la clé. Il reste peut être encore des traces dans le dump mémoire !

**NOTE :** *Vous vous demandez peut-être à quoi sert la présence d'`id` ? En règle générale, les opérateurs de rançongiciels n'ont pas qu'une seule victime. Chacune d'entre-elles possède une clé de chiffrement unique et il faut être en mesure des les identifier pour être en mesure de déchiffrer les données en cas de paiement de la rançon. De ce fait, un identifiant unique est attribué à chaque victime et est associé à la bonne clé de chiffrement. Attention, cela s'applique uniquement s'il y a une volonté de l'attaquant à déchiffrer les données. Il n'y a absolument **aucune garantie** qu'il respecte sa part du marché...*

### En résumé...

Bien, il est grand temps de faire le résumé de notre analyse. Ce que nous savons à présent : 

- L'identifiant unique associé à la clé de chiffrement est une suite aléatoire de 32 caractères hexadécimaux
- La clé de chiffrement est également une suite aléatoire de 32 caractères hexadécimaux
- Ceux-ci sont envoyés au serveur de l'attaquant à travers les paramètres respectifs `id` et `enckey` et mis en forme avec le modèle suivant : `{"id": "l'id", "enckey": "la clé"}`

Grâce à ces informations, nous pouvons passer à l'extraction de cette fameuse clé de chiffrement. 

## 2. Extraction de la clé de chiffrement 🗝

Nous devons trouver au sein du dump mémoire *la clé de chiffrement*. Pour ce faire, nous pouvons nous appuyer sur le modèle (ou *pattern* en anglais) d'envoi de la charge utile contenant `id` et `enckey` au serveur de l'attaquant. Quoi de mieux que `grep` pour retrouver un pattern dans un fichier ? :) 

### `grep` for the win 

`grep` est un outil très intéressant quand il s'agit de répérer des pattern au sein d'un fichier. Ici, nous allons lui ajouter plusieurs options. La commande finale est la suivante : `grep -B 3 -A 3 -wE '{"id": "\w{32}", "enckey":'`. Détaillons un peu plus ces options :

- L'option `-B 3` permet d'afficher 3 lignes **avant** la correspondance
- L'option `-A 3` permet d'afficher 3 lignes **après** la correspondance
- L'option `-wE` permet d'une part de n'afficher que les résultats correspondant exactement au pattern spécifié et d'autre part d'activer les expressions régulières étendues. 

Détail de l'expression régulière étendue `{"id": "\w{32}", "enckey":` : 

- `\w{32}` : permet de faire correspondre une chaîne de 32 caractères alphanumériques (avec le caractère `_` en supplément). C'est l'équivalent de  `[a-zA-Z0-9_]`

Maintenant que notre `grep` est prêt, nous pouvons l'utiliser sur le dump mémoire :

```bash
┌──(hashp4㉿kali)-[~/Bureau]
└─$ strings mem.dmp | grep -B 3 -A 3 -wE '{"id": "\w{32}", "enckey":'
"C:\Users\TNKLSAI3TGT7O9\Downloads\assistance.exe" 
C:\Users\TNKLSAI3TGT7O9\Downloads\assistance.exe
S-1-5-21-2377780471-3200203716-3353778491-1000
{"id": "cd18c00bb476764220d05121867d62de", "enckey": "
cd18c00bb476764220d05121867d62de64e0821c53c7d161099be2188b6cac24cd18c00bb476764220d05121867d62de64e0821c53c7d161099be2188b6cac2495511870061fb3a2899aa6b2dc9838aa422d81e7e1c2aa46aa51405c13fed15b95511870061fb3a2899aa6b2dc9838aa422d81e7e1c2aa46aa51405c13fed15b
Encrypting C:\Users\Administrateur\Contacts\desktop.ini...
C:\Users\TNKLSA~1\AppData\Local\Temp\desktop.ini
```

Il se trouve que nous avons belle et bien une correspondance ! 

```json
{
    "id": "cd18c00bb476764220d05121867d62de", 
    "enckey": "cd18c00bb476764220d05121867d62de64e0821c53c7d161099be2188b6cac24cd18c00bb476764220d05121867d62de64e0821c53c7d161099be2188b6cac2495511870061fb3a2899aa6b2dc9838aa422d81e7e1c2aa46aa51405c13fed15b95511870061fb3a2899aa6b2dc9838aa422d81e7e1c2aa46aa51405c13fed15b
```

Ici, l'`id` a donc pour valeur `cd18c00bb476764220d05121867d62de`. Cependant, la clé de chiffrement est bien plus grande que prévu. Nous devons donc découper celle-ci en paquet de 32 caractères. Pour ce faire, nous enregistrons manuellement la clé dans un fichier `key.txt`. Puis, nous pouvons utiliser l'utilitaire `fold` à l'aide de l'option `-b32` pour découper notre chaîne de caractère :

```bash
┌──(hashp4㉿kali)-[~/Bureau]
└─$ fold -b32 key.txt | sort | uniq
422d81e7e1c2aa46aa51405c13fed15b
64e0821c53c7d161099be2188b6cac24
95511870061fb3a2899aa6b2dc9838aa
cd18c00bb476764220d05121867d62de
```
*(L'utilisation de `sort` et `uniq` permet simplement d'enlever les paquets de 32 identiques).*

Nous nous retrouvons avec 4 candidats potentiels. Cela dit, nous remarquons que la dernière clé est en fait identique à l'`id` ! Il ne nous reste que 3 clés à tester. ;)

### Test des clés

Dans des conditions réelles, nous devrions analyser le code du rançongiciel, prendre connaissance de l'algorithme de chiffrement utilisé, dump un fichier chiffré depuis l'image mémoire et tenter de le déchiffrer avec chacune des clés potentielles. Cependant, dans le cadre de ce writeup, cela reviendrait à donner la solution pour la dernière étape de cette épreuve...

De ce fait, et compte-tenu de la faible proportion de clé à évaluer, il nous suffit de les tester une par une en tant que flag jusqu'à que celui-ci sois valide. 

- ❌ `ECSC{422d81e7e1c2aa46aa51405c13fed15b}`
- ❌ `ECSC{64e0821c53c7d161099be2188b6cac24}`
- ✅ `ECSC{95511870061fb3a2899aa6b2dc9838aa}`

## 3. Flag 🚩

Grâce à notre analyse (*et un trèèèèès léger bruteforce*), nous obtenons le flag suivant : `ECSC{95511870061fb3a2899aa6b2dc9838aa}`

Cela marque la conclusion de cette seconde partie du challenge `3615 Incident`. Dans un premier temps, nous avons pu voir comment était généré la clé de chiffrement et par quel moyen celle-ci était transmise à l'attaquant en étudiant le code source du rançongiciel. Dans un second temps, nous avons retrouvé celle associée à notre victime à l'aide d'une recherche de pattern dans l'image mémoire. Il ne vous reste plus que quelques efforts supplémentaires pour réussir la dernière étape de ce challenge. ;)
