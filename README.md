# Ultimate CSR ![alt text](https://pkiscape.com/img/favicon.png)
Ultimate CSR is a CLI tool that allows you to define more complex subject fields and x509v3 extensions for your CSR. 

Let me know if you'd like to see any other extensions or fields!

## Usage
```
usage: ultimatecsr.py [-h] (-p [PRIVATEKEY] | -k [CREATEKEY]) [-e] [-o OUT]

X509 Certificate Signing Request Maker

options:
  -h, --help            show this help message and exit
  -p [PRIVATEKEY], --privatekey [PRIVATEKEY]
                        Define your existing private key.
  -k [CREATEKEY], --createkey [CREATEKEY]
                        Creates a private key for you. If no name is provided, it uses "privatekey.pem"
  -e, --encrypt         Encrypt the private key you create with -k (--createkey)
  -o OUT, --out OUT     Define the CSR output filename
```

This tool allows you to:

- Define many subject fields such as Common Name, Email Address, UserID, Given Name, Title, Pseudonym and more!
- Request v3 extensions such as Key Usage, Extended Key Usage, Basic Constraints and Subject Alternative Names.

## Installation

Make sure Python Cryptography is up to date:

```
pip install --upgrade cryptography
```

Or, you can also use requirements.txt.
```
pip install -r requirements.txt
```


## Examples

Create a CSR defining an already existing private key ```great_privatekey.pem```, outputting the CSR to a file called ```mycsr.pem```.

```
python3 ultimatecsr.py -p great_privatekey.pem -o mycsr.pem
```

Create a private key (default name will be ```privatekey.pem```) without outputting the CSR to a file.
```
python3 ultimatecsr.py -k
```

Create a private key (```test_keypair.pem```) with encryption without outputting the CSR to a file.
```
python3 ultimatecsr.py -k test_keypair.pem -e
```


