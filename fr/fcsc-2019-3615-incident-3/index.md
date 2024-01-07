# [FCSC 2019] - 3615 Incident (3/3)


## Introduction :pushpin: 

Le contexte reste le même que lors de la première partie et seconde partie. Une victime de plus est tombée sous le coup d’un rançongiciel. Le paiement de la rançon n’est pas envisagée vu le montant demandé. Nous sommes donc appelés pour essayer de restaurer les fichiers chiffrés.

Cette fois-ci, l'objectif est de **déchiffrer le fichier data ci-joint**.

(La résolution de l'épreuve s'effectue toujours à l'aide du fichier `mem.dmp.tar.xz`. Pour rappel, il s'agit d'une image mémoire de l'ordinateur de la victime. Concrètement, celle-ci correspond au contenu de la mémoire volatile (`RAM`) au moment de l'acquisition. De plus, nous avons à disposition le fichier `data` à déchiffrer.

## 1. Étude de l'algorithme de chiffrement 📋

Pour pouvoir déchiffrer le fichier `data`, nous allons devoir étudier l'algorithme de chiffrement mis en place par ce rançongiciel. Comme nous avons accès au code source, cela simplifie grandement le processus.

### Un zoom rapide sur `ransomware.go` (encore oui)

Replongeons nous dans le fichier [/cmd/ransomware/ransomware.go, ligne 223](https://github.com/mauri870/ransomware/blob/master/cmd/ransomware/ransomware.go#L223) cette fois ci.

```go
// Encrypt the file sending the content to temporary file
err = file.Encrypt(keys["enckey"], tempFile)
if err != nil {
    cmd.Logger.Println(err)
    continue
}
```
Nous pouvons constater que la fonction de chiffrement `Encrypt()` provient du fichier `file`. Elle semble prendre en paramètre la clé de chiffrement et un nom de fichier temporaire. Il est donc nécessaire d'analyser ce que fais précisemment cette fameuse fonction.

### Un zoom sur `file.go`

Le fonctionnement de l'algorithme de chiffrement employé par la fonction `Encrypt()` se trouve à partir de [la ligne 21 du fichier cryptofs/file.go](https://github.com/mauri870/ransomware/blob/master/cryptofs/file.go#L21).

```go
func (file *File) Encrypt(enckey string, dst io.Writer) error {
	[...]
	// Create a 128 bits cipher.Block for AES-256
	block, err := aes.NewCipher([]byte(enckey))
	if err != nil {
		return err
	}

	// The IV needs to be unique, but not secure
	iv := make([]byte, aes.BlockSize)
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}

	// Get a stream for encrypt/decrypt in counter mode (best performance I guess)
	stream := cipher.NewCTR(block, iv)

	// Write the Initialization Vector (iv) as the first block
	// of the dst writer
	dst.Write(iv)
    [...]
}
```

Le première partie du code nous permet de constater l'utilisation de l'algorithme de chiffrement `AES-256`. Le chiffrement s'effectue en *counter mode (CTR)*, observable un peu plus bas. 

Le second partie du code, quant à elle, nous indique que l'`IV` est **le premier bloc** du fichier chiffré. C'est une bonne nouvelle pour nous. En effet, comme nous disposons des fichiers chiffrés et de la clé de chiffrement, il nous suffit d'extraire l'IV de ceux-ci pour pouvoir les déchiffrer. 

## 2. Déchiffrement du fichier `data` 🔓

### Extraction de l'IV

Pour extraire l'`IV` de `data`, nous pouvons utiliser `xxd` pour obtenir le contenu du fichier en hexadécimal et `fold` pour le découper en bloc de 32 caractères *(rappelez-vous, l'IV est une chaine de 32 caractères hexadécimaux)*. Ensuite, nous pouvons utiliser `head` pour ne garder que le premier bloc à l'aide de l'option `-n 1`. 

```bash
┌──(hashp4㉿kali)-[~/Bureau]
└─$ xxd -p data | fold -b32 | head -n 1                
b627d24fc90dfe7ce421c43312dc2f2e
```

Ainsi, nous obtenons l'`IV` correspondant à notre fichier `data` : `b627d24fc90dfe7ce421c43312dc2f2e` 


### Déchiffrement via Cyberchef *(flemmard)*

Pour déchiffrer notre fichier, nous pouvons nous aider de [Cyberchef](https://gchq.github.io/CyberChef/). Pour ce faire, il faut lui donner un entrée (*input*) le contenu du fichier chiffré (ici *data*) en hexadécimal. Pour ce faire nous pouvons utiliser `xxd`. 

*(⚠️ : n'oublions pas de supprimer le contenu correspondant à l'IV de notre fichier, sans quoi le déchiffrement ne marchera pas. Nous utilisons l'outil `sed` pour le faire).*

```bash
┌──(hashp4㉿kali)-[~/Bureau]
└─$ xxd -p -c0 data | sed 's/b627d24fc90dfe7ce421c43312dc2f2e//g'
abf961d204bf8c684dff45fc658d5bba4da43a8 [...]7febfd28649595e720a8
```
*Le résultat étant trop grand, je n'écris ici que les caractères correspondant au début et à la fin du fichier.*

Nous devons ensuite copier/coller ce résultat dans Cyberchef, sélectionner la recette `AES Decrypt` et rentrer les paramètres suivants : 

- **Key (UTF-8) :** `95511870061fb3a2899aa6b2dc9838aa`
- **IV (HEX) :** `b627d24fc90dfe7ce421c43312dc2f2e`
- **Mode :** `CTR`
- **Input :** `HEX`
- **Output :** `RAW`

<img width="704" alt="dechiffrement-cyberchef" src="https://gist.github.com/assets/92587864/af7c8e2c-bc6a-4864-9ee6-9aca0bf3f1c3">

Nous pouvons remarquer que le déchiffrement semble bien effectif puisque nous remarquons le header d'un fichier ZIP `50 4b 03 04` correspondant à `PK` et d'autres chaines de caractères telles que : 

- *_rels/.rels*
- *docProps/core.xml*
- *docProps/app.xml*
- *word/_rels/document.xml.rels*
- *word/document.xml*
*[...]*

Celles-ci nous portent à croire que nous avons à faire à un document Word. Notre fichier serait donc l'équivalent de `flag.docx` que nous avions trouvé lors de la première partie de cette épreuve. Nous pouvons ensuite télécharger le fichier sur notre machine. Ici, nous le nommons `flag.zip`. Nous pouvons maintenant le dézipper :

```bash
┌──(hashp4㉿kali)-[~/Bureau]
└─$ unzip flag.zip                                                            
Archive:  flag.zip
  inflating: _rels/.rels             
  inflating: docProps/core.xml       
  inflating: docProps/app.xml        
  inflating: word/_rels/document.xml.rels  
  inflating: word/document.xml       
  inflating: word/styles.xml         
  inflating: word/fontTable.xml      
  inflating: word/settings.xml       
  inflating: [Content_Types].xml
```

Le contenu d'un fichier word se trouve en général dans le document `word/document.xml`. Nous pouvons donc utiliser `grep` pour afficher directement le flag sans s'embêter à l'ouvrir :

```bash
┌──(hashp4㉿dragon)-[~/Bureau]
└─$ grep "ECSC{" word/document.xml 
[...]
</w:rPr><w:t>Flag: ECSC{M4ud1t3_C4mp4gn3_2_r4NC0nG1c13L}</w:t></w:r></w:p><w:sectPr>
[...]
```
Et voilà ! Le déchiffrement est un succès. Regardons maintenant une autre manière de faire. 


### Déchiffrement via Python *(street cred++)*

Pour déchiffrer notre fichier `data`, nous pouvons également faire appel à notre talent de programmeur (*ou appel à notre ami ChatGPT :p*). Ayant une plus grande familiarité avec Python, c'est avec celui-ci que nous allons pouvoir déchiffrer notre fichier. Cependant, libre à vous de choisir un autre langage de programmation pour cet exercice. 

Voici le script `decrypt.py` en question : 

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def decrypt_file(input_file, output_file, key):
    # Read encrypted content from file
    with open(input_file, 'rb') as file:
        encrypted_content = file.read()

    # Extract IV (first 32 characters)
    iv = encrypted_content[:16]
    print(f"The IV of the file is : {iv.hex()}")
    encrypted_data = encrypted_content[16:]

    # Initialize AES-CTR cipher
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=backend)
    decryptor = cipher.decryptor()

    # Decrypt the content
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Write the decrypted content to the output file
    with open(output_file, 'wb') as file:
        file.write(decrypted_data)

def main():
    input_file = input("Enter the path to the encrypted file: ")
    output_file = input("Enter the path for the output file (decrypted content): ")
    key = input("Enter the AES key: ").encode("utf-8")

    flag = decrypt_file(input_file, output_file, key)
    
    print(f"Decryption completed. Decrypted content saved in '{output_file}'.")

if __name__ == "__main__":
    main()
```

Le principe est simple : 
- Demander à l'utilisateur **le chemin du fichier chiffré**
- Demander à l'utilisateur **le chemin et le nom du fichier dans lequel il souhaite mettre le contenu déchiffré**
- Demander à l'utilisateur **la clé de déchiffrement**

Ensuite, ce script va **extraire automatiquement l'IV** du fichier chiffré, l'afficher à l'utilisateur et enfin déchiffrer son contenu. 

*Il serait intéressant de modifier ce script pour pouvoir déchiffrer tous les fichiers ayant pour extension `.chiffré` et de nommer ceux-ci par leur nom original (il suffit de décoder leur nom en `base64`).*

Voici un exemple d'utilisation :

```bash
┌──(hashp4㉿kali)-[~/Bureau]
└─$ python3 decrypt.py 
Enter the path to the encrypted file: data
Enter the path for the output file (decrypted content): /tmp/flag
Enter the AES key: 95511870061fb3a2899aa6b2dc9838aa
The IV of the file is : b627d24fc90dfe7ce421c43312dc2f2e
Decryption completed. Decrypted content saved in '/tmp/flag'.
```

Nous pouvons vérifier le type du fichier à l'aide de `file` :

```bash
┌──(hashp4㉿kali)-[~/Bureau]
└─$ file /tmp/flag 
/tmp/flag: Microsoft Word 2007+
```

Le script est fonctionnel puisque la commande détecte bien le fichier déchiffré comme un document Word. Nous pouvons donc le dézipper et utiliser le même `grep` que précédemment :

```bash
┌──(hashp4㉿dragon)-[~/Bureau]
└─$ grep "ECSC{" /tmp/word/document.xml 
[...]
</w:rPr><w:t>Flag: ECSC{M4ud1t3_C4mp4gn3_2_r4NC0nG1c13L}</w:t></w:r></w:p><w:sectPr>
[...]
```

Nous retrouvons bien notre flag. :D


## 3. Flag 🚩

Nous avons donc réussi à aider notre victime à déchiffrer ses fichiers.

Le flag pour cette dernière épreuve est donc : `ECSC{M4ud1t3_C4mp4gn3_2_r4NC0nG1c13L}`.

Ce troisième et dernier challenge marque la fin de l'épreuve. Je vous remercie d'avoir lu mes writeups et espère avoir été assez clair dans mes explications. N'hésitez pas à me faire vos retours en me contactant directement sur Discord ou Twitter. ;)


## BONUS - Retrouver le flag sans le fichier `data` 💡

Etant de nature curieuse, j'ai voulu voir s'il était possible de retrouver le flag directement à l'aide du fichier `flag.docx` chiffré (*ZmxhZy5kb2N4.chiffré*) à partir du dump mémoire. Pour rappel, nous avions trouvé son adresse virtuelle dans le dump suite à l'utilisation du plugin `windows.filescan` de **Volatility3**.

```bash
┌──(hashp4㉿kali)-[~/Bureau]
└─$ python3 ~/Tools/volatility3/vol.py -f mem.dmp windows.filescan | grep "ZmxhZy5kb2N4" 
0xe000123988d0.0\ZmxhZy5kb2N4.chiffré   216
```

De ce fait, j'ai ensuite récupéré le fichier à l'aide du plugin `windows.dumpfiles` et de l'option `--virtaddr` suivie de l'adresse virtuelle de `ZmxhZy5kb2N4.chiffré`.

```bash
┌──(hashp4㉿kali)-[~/Bureau]
└─$ python3 vol.py -f mem.dmp windows.dumpfiles --virtaddr 0xe000123988d0  
Volatility 3 Framework 2.5.2
Progress:  100.00               PDB scanning finished                                
Cache   FileObject      FileName        Result

DataSectionObject       0xe000123988d0  ZmxhZy5kb2N4.chiffré    file.0xe000123988d0.0xe00010401370.DataSectionObject.ZmxhZy5kb2N4.chiffré.dat
```

J'ai ensuite exécuté mon script Python sur le fichier chiffré :

```bash
┌──(hashp4㉿kali)-[~/Bureau]
└─$ python3 decrypt.py 
Enter the path to the encrypted file: ZmxhZy5kb2N4.chiffré
Enter the path for the output file (decrypted content): /tmp/flag
Enter the AES key: 95511870061fb3a2899aa6b2dc9838aa
The IV of the file is : b627d24fc90dfe7ce421c43312dc2f2e
Decryption completed. Decrypted content saved in '/tmp/flag'.
                                                                                                                                    
┌──(hashp4㉿kali)-[~/Bureau]
└─$ file /tmp/flag 
/tmp/flag: Microsoft Word 2007+
```

Celui-ci étant bel et bien considéré comme un document Word, je l'ai dézippé et j'ai utilisé `grep` pour en extraire le flag :

```bash
┌──(hashp4㉿dragon)-[~/Bureau]
└─$ grep "ECSC{" /tmp/word/document.xml 
[...]
</w:rPr><w:t>Flag: ECSC{M4ud1t3_C4mp4gn3_2_r4NC0nG1c13L}</w:t></w:r></w:p><w:sectPr>
[...]
```

Il est donc possible de résoudre cette dernière épreuve sans s'appuyer sur le fichier `data` ci-joint.
