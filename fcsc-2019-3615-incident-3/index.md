# [FCSC 2019] - 3615 Incident (3/3)


## Introduction :pushpin: 

The context remains the same as in Part 1 and Part 2. Yet another victim has fallen victim to ransomware. Payment of the ransom is not an option, given the amount involved. So we're called in to try and restore the encrypted files.

This time, the objective is to **decrypt the attached data file**.

(The challenge is always solved using the `mem.dmp.tar.xz` file. As a reminder, this is a memory image of the victim's computer. In concrete terms, it corresponds to the contents of volatile memory (`RAM`) at the time of acquisition. We also have the `data` file to decrypt.)

## 1. Study of the encryption algorithm 📋

In order to decrypt the `data` file, we'll need to study the encryption algorithm implemented by this ransomware. Since we have access to the source code, this greatly simplifies the process.

### Zoom on `ransomware.go` (again, yes)

Let's go back to the file [/cmd/ransomware/ransomware.go, line 223](https://github.com/mauri870/ransomware/blob/master/cmd/ransomware/ransomware.go#L223) this time.

```go
// Encrypt the file sending the content to temporary file
err = file.Encrypt(keys["enckey"], tempFile)
if err != nil {
    cmd.Logger.Println(err)
    continue
}
```
We can see that the `Encrypt()` encryption function comes from the `file` file. It seems to take the encryption key and a temporary file name as parameters. It is therefore necessary to analyze what exactly this function does.

### Zoom on `file.go`

The encryption algorithm used by the `Encrypt()` function can be found in [line 21 of the cryptofs/file.go file](https://github.com/mauri870/ransomware/blob/master/cryptofs/file.go#L21).

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

The first part of the code shows the use of the AES-256 encryption algorithm. Encryption is carried out in *counter mode (CTR)*, as can be seen below. 

The second part of the code tells us that the `IV` is **the first block** of the encrypted file. This is good news for us. Since we have the encrypted files and the encryption key, all we need to do to decrypt them is extract the IV from them.

## 2. Decrypting the `data` file 🔓

### IV Extraction

To extract the `IV` from `data`, we can use `xxd` to get the file contents in hexadecimal and `fold` to split it into 32-character blocks *(remember, the IV is a 32-character hexadecimal string)*. Then we can use `head` to keep only the first block, using the `-n 1` option.

```bash
┌──(hashp4㉿kali)-[~/Bureau]
└─$ xxd -p data | fold -b32 | head -n 1                
b627d24fc90dfe7ce421c43312dc2f2e
```

In this way, we obtain the `IV` corresponding to our `data` file : `b627d24fc90dfe7ce421c43312dc2f2e` 


### Decryption with Cyberchef *(lazy way)*

To decrypt our file, we can use [Cyberchef](https://gchq.github.io/CyberChef/). To do this, we need to give it an input (*input*) the contents of the encrypted file (here *data*) in hexadecimal. To do this, we can use `xxd`. 

{{< admonition warning >}}
Don't forget to delete the contents corresponding to the IV of our file, otherwise decryption won't work. We use the `sed` tool to do this.
{{< /admonition >}}

```bash
┌──(hashp4㉿kali)-[~/Bureau]
└─$ xxd -p -c0 data | sed 's/b627d24fc90dfe7ce421c43312dc2f2e//g'
abf961d204bf8c684dff45fc658d5bba4da43a8 [...]7febfd28649595e720a8
```
*As the result is too large, I will only write the characters corresponding to the beginning and end of the file here.

We then need to copy/paste this result into Cyberchef, select the `AES Decrypt` recipe and enter the following parameters:

- **Key (UTF-8) :** `95511870061fb3a2899aa6b2dc9838aa`
- **IV (HEX) :** `b627d24fc90dfe7ce421c43312dc2f2e`
- **Mode :** `CTR`
- **Input :** `HEX`
- **Output :** `RAW`

<img width="704" alt="dechiffrement-cyberchef" src="https://gist.github.com/assets/92587864/af7c8e2c-bc6a-4864-9ee6-9aca0bf3f1c3">

We can see that decryption seems to be effective, since we can see the header of a ZIP file `50 4b 03 04` corresponding to `PK` and other strings such as : 

- *_rels/.rels*
- *docProps/core.xml*
- *docProps/app.xml*
- *word/_rels/document.xml.rels*
- *word/document.xml*
*[...]*

These lead us to believe that we are dealing with a Word document. Our file would therefore be the equivalent of `flag.docx` that we found in the first part of this test. We can then download the file to our machine. Here, we call it `flag.zip`. We can now unzip it:

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

The content of a word file is usually found in the `word/document.xml` document. We can therefore use `grep` to display the flag directly without having to open it:

```bash
┌──(hashp4㉿dragon)-[~/Bureau]
└─$ grep "ECSC{" word/document.xml 
[...]
</w:rPr><w:t>Flag: ECSC{M4ud1t3_C4mp4gn3_2_r4NC0nG1c13L}</w:t></w:r></w:p><w:sectPr>
[...]
```
And that's it! The decryption is a success. Now let's look at another way of doing it.


### Decrypting with Python *(street credibility++)*

To decrypt our `data` file, we can also call on our programming skills (*or call on our friend ChatGPT :p*). Since we're more familiar with Python, we'll use it to decrypt our file. However, you're free to choose another programming language for this exercise. 

Here's the `decrypt.py` script in question:

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

The principle is simple: 
- Ask the user **the path to the encrypted file**.
- Ask the user for **the path and name of the file in which to store the decrypted content**.
- Ask the user for **the decryption key**.

Then, this script will **automatically extract the IV** from the encrypted file, display it to the user and finally decrypt its contents. 

*It would be interesting to modify this script so as to be able to decrypt all files with the extension `.encrypted' and name them by their original name (just decode their name in `base64').

Here's an example:

```bash
┌──(hashp4㉿kali)-[~/Bureau]
└─$ python3 decrypt.py 
Enter the path to the encrypted file: data
Enter the path for the output file (decrypted content): /tmp/flag
Enter the AES key: 95511870061fb3a2899aa6b2dc9838aa
The IV of the file is : b627d24fc90dfe7ce421c43312dc2f2e
Decryption completed. Decrypted content saved in '/tmp/flag'.
```

We can check the file type using `file` :

```bash
┌──(hashp4㉿kali)-[~/Bureau]
└─$ file /tmp/flag 
/tmp/flag: Microsoft Word 2007+
```

The script works, since the command correctly detects the decrypted file as a Word document. We can now unzip it and use the same `grep` as before:

```bash
┌──(hashp4㉿dragon)-[~/Bureau]
└─$ grep "ECSC{" /tmp/word/document.xml 
[...]
</w:rPr><w:t>Flag: ECSC{M4ud1t3_C4mp4gn3_2_r4NC0nG1c13L}</w:t></w:r></w:p><w:sectPr>
[...]
```

We've got our flag back. :D


## 3. Flag 🚩

We have therefore succeeded in helping our victim to decrypt his files.

The flag for this final challenge is: `ECSC{M4ud1t3_C4mp4gn3_2_r4NC0nG1c13L}`.

This third and final challenge marks the end of the event. I'd like to thank you for reading my writeups and hope I've made my explanations clear enough. Don't hesitate to give me your feedback by contacting me directly on Discord or Twitter ;)


## BONUS - Find the flag without the `data` file 💡

Being curious by nature, I wanted to see if it was possible to find the flag directly using the encrypted `flag.docx` file (*ZmxhZy5kb2N4.encrypted*) from the memory dump. As a reminder, we had found its virtual address in the dump using the `windows.filescan` plugin from **Volatility3**.

```bash
┌──(hashp4㉿kali)-[~/Bureau]
└─$ python3 ~/Tools/volatility3/vol.py -f mem.dmp windows.filescan | grep "ZmxhZy5kb2N4" 
0xe000123988d0.0\ZmxhZy5kb2N4.chiffré   216
```

I then recovered the file using the `windows.dumpfiles` plugin and the `--virtaddr` option, followed by the virtual address of `ZmxhZy5kb2N4.encrypted`.

```bash
┌──(hashp4㉿kali)-[~/Bureau]
└─$ python3 vol.py -f mem.dmp windows.dumpfiles --virtaddr 0xe000123988d0  
Volatility 3 Framework 2.5.2
Progress:  100.00               PDB scanning finished                                
Cache   FileObject      FileName        Result

DataSectionObject       0xe000123988d0  ZmxhZy5kb2N4.chiffré    file.0xe000123988d0.0xe00010401370.DataSectionObject.ZmxhZy5kb2N4.chiffré.dat
```

I then ran my Python script on the encrypted file:

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

As this is indeed considered a Word document, I unzipped it and used `grep` to extract the flag :

```bash
┌──(hashp4㉿dragon)-[~/Bureau]
└─$ grep "ECSC{" /tmp/word/document.xml 
[...]
</w:rPr><w:t>Flag: ECSC{M4ud1t3_C4mp4gn3_2_r4NC0nG1c13L}</w:t></w:r></w:p><w:sectPr>
[...]
```

It is therefore possible to solve this last test without relying on the attached `data` file.
