# [FCSC 2019] - 3615 Incident (2/3)


## Introduction :pushpin:

The context remains the same as in the first part. Yet another victim has fallen victim to ransomware. Payment of the ransom is not an option, given the amount involved. So we're called in to try and restore the encrypted files.

This time, the objective is to **find the ransomware's encryption key**!

Note: Answer expected in `ECSC{hey.hex()}` format.

(The challenge is always solved using the `mem.dmp.tar.xz` file. As a reminder, this is a memory image of the victim's computer. In concrete terms, it corresponds to the contents of the volatile memory (`RAM`) at the time of acquisition, and we'll see that it proves to be an excellent source of information for digital forensics.)

## 1. Analysis of the ransomware's source code 🔬

Following our analysis in Part 1, we are fortunate to have the source code for this ransomware. As a reminder, it can be found here: https://github.com/mauri870/ransomware. And that's a good thing, because we didn't really want to reverse the Go, did we? :D

### Zoom on `ransomware.go`

Let's start by finding out how the key is generated. The `encryptFile()` function in the file [cmd/ransomware/ransomware.go, line 112](https://github.com/mauri870/ransomware/blob/master/cmd/ransomware/ransomware.go#L112) tells us a bit more.

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

We can see 2 things: 
- The generation of an `id` using the `GenerateRandomANString()` function located in the `utils` file and having the `32` parameter.
- The generation of `enckey` using the `GenerateRandomANString()` function located in the `utils` file and having `32` as parameter.

This `id` and `enckey` pair is then sent to a server using the `AddNewKeyPair()` function in the `client` file.

We can assume that both `id` and the encryption key `enckey` (*which is surely short for `encrypted key`*) are a randomly generated 32-character string. To be sure, we can study the corresponding function.

### Zoom on `utils.go`

Here, we're interested in the `GenerateRandomANString()` function, [on line 13 of utils/utils.go](https://github.com/mauri870/ransomware/blob/master/utils/utils.go#L13).

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

The function is quite simple. It takes an integer as parameter and generates a random string of the same size. This is then encoded in hexadecimal using the function `hex.EncodeToString()` before being returned. 

Our hypothesis is therefore confirmed. We're looking for a 32-character string, and we know it's hexadecimal. But we still have no clue as to how to retrieve this famous key...


### Zoom on `client.go`

Let's take a closer look at the `AddNewKeyPair()` function [in client/client.go, line 90](https://github.com/mauri870/ransomware/blob/master/client/client.go#L90).

```go
// AddNewKeyPair persist a new keypair on server
func (c *Client) AddNewKeyPair(id, encKey string) (*http.Response, error) {
	payload := fmt.Sprintf(`{"id": "%s", "enckey": "%s"}`, id, encKey)
	return c.SendEncryptedPayload("/api/keys/add", payload, map[string]string{})
}
```

This function takes an `id` and an `enckey` encryption key as parameters. It will then format the payload as:

```json
{
    "id": "l'id associé",
    "enckey": "la clé de chiffrement"
}
```

It will then be encrypted and sent to the attacker's server via an API through the URI `/api/key/add` via the function `SendEncryptedPayload()` *(I'll leave it to you to look at this function in more detail if you're interested)*. So it's worth concentrating on sending this payload to find the key. There may still be traces left in the memory dump!

{{< admonition info >}}
*You may be wondering what the `id` is for? As a rule, ransomware operators don't have just one victim. Each of them has a unique encryption key, and you need to be able to identify them to be able to decrypt the data if the ransom is paid. For this reason, a unique identifier is assigned to each victim and associated with the correct encryption key. However, this only applies if the attacker is willing to decrypt the data. There is absolutely **no guarantee** that he will keep his end of the bargain...*.
{{< /admonition >}}

### In a nutshell...

Well, it's time to summarize our analysis. What we know now: 

- The unique identifier associated with the encryption key is a random sequence of 32 hexadecimal characters.
- The encryption key is also a random sequence of 32 hexadecimal characters.
- These are sent to the attacker's server via the respective parameters `id` and `enckey`, and formatted according to the following model: `{"id": "the id", "enckey": "the key"}`.

With this information, we can move on to extracting the encryption key.

## 2. Extraction of the encryption key 🗝

We need to find the *encryption key* within the memory dump. To do this, we can use the *pattern* that sends the payload containing `id` and `enckey` to the attacker's server. What could be better than `grep` to find a pattern in a file? :)

### `grep` for the win 

`grep` is a very interesting tool when it comes to repeating patterns within a file. Here, we'll add several options. The final command is: `grep -B 3 -A 3 -wE '{"id": "\w{32}", "enckey":'`. Let's take a closer look at these options:

- The `-B 3` option displays 3 lines **before** the match
- The `-A 3` option displays 3 lines **after** the match
- The `-wE` option allows you to display only results that exactly match the specified pattern, and to activate extended regular expressions. 

Extended regular expression detail `{"id":"\w{32}", "enckey":` : 

- `\w{32}`: matches a string of 32 alphanumeric characters (with the `_` character added). It's the equivalent of `[a-zA-Z0-9_]`.

Now that our `grep` is ready, we can use it on the memory dump:

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

As it turns out, we do have a correspondence!

```json
{
    "id": "cd18c00bb476764220d05121867d62de", 
    "enckey": "cd18c00bb476764220d05121867d62de64e0821c53c7d161099be2188b6cac24cd18c00bb476764220d05121867d62de64e0821c53c7d161099be2188b6cac2495511870061fb3a2899aa6b2dc9838aa422d81e7e1c2aa46aa51405c13fed15b95511870061fb3a2899aa6b2dc9838aa422d81e7e1c2aa46aa51405c13fed15b
```

Here, the `id` has the value `cd18c00bb476764220d05121867d62de`. However, the encryption key is much larger than expected. We therefore need to break it down into 32-character packets. To do this, we manually save the key in a `key.txt` file. Then we can use the `fold` utility, with the `-b32` option, to split our string:

```bash
┌──(hashp4㉿kali)-[~/Bureau]
└─$ fold -b32 key.txt | sort | uniq
422d81e7e1c2aa46aa51405c13fed15b
64e0821c53c7d161099be2188b6cac24
95511870061fb3a2899aa6b2dc9838aa
cd18c00bb476764220d05121867d62de
```
*(Using `sort` and `uniq` simply removes identical packets of 32).*

We end up with 4 potential candidates. That said, we notice that the last key is in fact identical to the `id`! We've only got 3 keys left to test ;)

### Keys testing

Under real-life conditions, we'd have to analyze the ransomware code, learn about the encryption algorithm used, dump an encrypted file from the memory image and attempt to decrypt it with each of the potential keys. However, in the context of this writeup, this would be tantamount to giving away the solution to the last stage of this test...

For this reason, and given the small proportion of keys to be evaluated, we need only test them one by one as a flag until the flag is valid.

- ❌ `ECSC{422d81e7e1c2aa46aa51405c13fed15b}`
- ❌ `ECSC{64e0821c53c7d161099be2188b6cac24}`
- ✅ `ECSC{95511870061fb3a2899aa6b2dc9838aa}`

## 3. Flag 🚩

Thanks to our analysis (*and a very liiiiiight bruteforce*), we obtain the following flag: `ECSC{95511870061fb3a2899aa6b2dc9838aa}`.

This concludes the second part of the `3615 Incident` challenge. Firstly, we were able to see how the encryption key was generated and how it was transmitted to the attacker by studying the ransomware source code. Secondly, we found the key associated with our victim using a pattern search in the memory image. All that's left is for you to make a few more efforts to complete the final stage of this challenge ;)
