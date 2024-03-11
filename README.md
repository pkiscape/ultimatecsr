# Ultimate CSR ![alt text](https://pkiscape.com/img/favicon.png)

Ultimate CSR is a semi-interactive CLI tool that allows you to define more complex subject fields and x509v3 extensions for your CSR.
It's similar to the ```openssl req``` command.

Let me know if you'd like to see any other extensions!

```
usage: ultimatecsr.py 

Possible Parameters:

-ck, --create-key [PRIVATE_KEY_FILENAME] | Creates a private key for you. If no name is provided, it uses 'privatekey.pem'.
-p, --private-key [PRIVATE_KEY_FILENAME] |  Define your existing private key filename
-e, --encrypt | Encrypt the private key you create with --create-key
-o OUT, --out [CSR_FILENAME] | Write CSR output to defined filename
-pkf, --private-key-format [PKCS1, PKCS8, OPENSSH] | When creating a private key with --create-key, choose the format it gets created. Default (PKCS8)
-ka, --key-algorithm [RSA2048,RSA4096,SECP256R1,SECP384R1,SECP521R1,SECP256K1] | Define the algorithm and key size of the private key you define with --create-key. Default (SECP384R1)
-ha, --hash-algorithm [SHA224,SHA256,SHA384,SHA512,SHA3_224,SHA3_256,SHA3_384,SHA3_512] | Define the hashing algorithm (Signature Algorithm). Default(SHA256).
-v, --verbose | Enable verbosity (more wordiness)
-m, --mode [short, long] | Short prompt mode: Only display common distringuished names. Skips extensions. Default(long)
-h, --help | Display help message   
```

This tool allows you to:

- Don't have a private key to start off with? Create one with one of the supported algorithms! If you do, you can define your own private key!
- Define your distinguished name with fields such as Common Name, Email Address, UserID, Given Name, Title, Pseudonym and more!
- Request X509v3 extensions such as Key Usage, Extended Key Usage, Basic Constraints and Subject Alternative Names(DNS names and IPv4 addresses).
- Define your own Extended Key Usage OIDs! (v6 new addition)


## Prerequisites

Install dependencies
```
pip install -r requirements.txt
```

Make sure that Python Cryptography is up to date!

```
pip install --upgrade cryptography
```

## Examples:

Create a CSR defining an already existing private key (great_privatekey.pem), outputting the CSR to a file called "mycsr.pem". 

```
python3 ultimatecsr.py -p great_privatekey.pem -o mycsr.pem
```

Create a private key (default name will be privatekey.pem) without outputting the CSR to a file. Default key algorithm will be SECP384R1. Default private key format is PKCS8. Use verbosity.
```
python3 ultimatecsr.py -ck -v
```

Create a private key (default name will be privatekey.pem) using the algorithm "RSA4096" outputting the CSR to a file "mycsr.pem". Private key format will be OpenSSH
```
python3 ultimatecsr.py -ck -ka rsa4096 -o mycsr.pem -pkf OPENSSH
```


Create a private key (test_keypair.pem) using the ECC curve "SECP521R1" with encryption outputting the CSR to a file "mycsr.pem". Use PKCS1 formatting for private key
```
python3 ultimatecsr.py -ck test_keypair.pem -ka SECP521R1 -e -o mycsr.pem -pkf PKCS1
```

Create a CSR defining your already existing private key (great_privatekey.pem), outputting the CSR to a file called "mycsr.pem", using the SHA512 hashing algorithm

```
python3 ultimatecsr.py -p great_privatekey.pem -o mycsr.pem -ha SHA512
```

Create a CSR defining your already existing private key (great_privatekey.pem), outputting the CSR to a file called "mycsr.pem". Use short mode (only prompt common Distinguished Names). 

```
python3 ultimatecsr.py -p great_privatekey.pem -o mycsr.pem -m short
```
