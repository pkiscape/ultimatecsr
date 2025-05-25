# Ultimate CSR ![alt text](https://pkiscape.com/img/favicon.png)

Ultimate CSR is a  tool that allows you to define more complex subject fields and x509v3 extensions for your CSR.

It is divided into two modes: CLI and Templates. 

- CLI: Allows you to use a Semi-interactive CLI to define the fields and attributes for your CSR. It's good for single CSR use or testing.
- Template: Allows you to pass a template where you define the fields and attributes for your CSR. It's good for bulk CSR creation and automation. 

### Features
With both the template and CLI modes, you have access to a lot of featuers.

- Don't have a private key to start off with? Create one with one of the supported algorithms! If you do, you can define your own private key!
- Define your distinguished name with fields such as Common Name, Email Address, UserID, Given Name, Title, Pseudonym and more!
- Request X509v3 extensions such as Key Usage, Extended Key Usage, Basic Constraints and Subject Alternative Names(DNS names and IPv4 addresses).
- Define your own Extended Key Usage and Subject OIDs!

### Important notes:

- Check the output folder. 
- If specified, CSRs will be written to the "csr" folder.
- Put your existing private keys in the "private_keys" folder.
- Put your templates in the "templates" folder.

## General Usage 

```
usage: ultimatecsr [-h] {cli,template} ...

Ultimate CSR Tool

positional arguments:
  {cli,template}
    cli           Interactive CLI-based CSR generation
    template      JSON template-based CSR generation

```
## CLI mode Usage "ultimatecsr.py cli"

```
usage: ultimatecsr cli [-h] [-p [PRIVATE_KEY]] [-ck [CREATE_KEY]] [-pkf {PKCS1,PKCS8,OPENSSH}] [-ka {RSA2048,RSA4096,SECP256R1,SECP384R1,SECP521R1,SECP256K1}] [-e]
                       [-o OUT] [-ha {SHA224,SHA256,SHA384,SHA512,SHA3_224,SHA3_256,SHA3_384,SHA3_512}] [-v] [-m {short,long}]

options:
  -h, --help            show this help message and exit
  -p [PRIVATE_KEY], --private-key [PRIVATE_KEY]
                        Define your existing private key.
  -ck [CREATE_KEY], --create-key [CREATE_KEY]
                        Create a private key.
  -pkf {PKCS1,PKCS8,OPENSSH}, --private-key-format {PKCS1,PKCS8,OPENSSH}
  -ka {RSA2048,RSA4096,SECP256R1,SECP384R1,SECP521R1,SECP256K1}, --key-algorithm {RSA2048,RSA4096,SECP256R1,SECP384R1,SECP521R1,SECP256K1}
  -e, --encrypt         Encrypt the private key
  -o OUT, --out OUT     CSR output filename
  -ha {SHA224,SHA256,SHA384,SHA512,SHA3_224,SHA3_256,SHA3_384,SHA3_512}, --hash-algorithm {SHA224,SHA256,SHA384,SHA512,SHA3_224,SHA3_256,SHA3_384,SHA3_512}
  -v, --verbose
  -m {short,long}, --mode {short,long}
```

## Template mode Usage "ultimatecsr.py template"
**Put in your JSON templates in the templates directory**

```
usage: ultimatecsr template [-h] [-t [TEMPLATE]] [-o] [-v]

options:
  -h, --help            show this help message and exit
  -t [TEMPLATE], --template [TEMPLATE]
                        Define your template file.
  -o, --out             Print the CSR PEM
  -v, --verbose
```

## Template Guide

See the [Template Guide](template_guide.md)

## Prerequisites

Install dependencies
```
pip install -r requirements.txt
```

Make sure that Python Cryptography is up to date!

```
pip install --upgrade cryptography
```

## CLI Examples:

Create a CSR defining an already existing private key (great_privatekey.pem), outputting the CSR to a file called "mycsr.pem". 

```
python3 ultimatecsr.py cli -p great_privatekey.pem -o mycsr.pem
```

Create a private key (default name will be privatekey.pem) without outputting the CSR to a file. Default key algorithm will be SECP384R1. Default private key format is PKCS8. Use verbosity.
```
python3 ultimatecsr.py cli -ck -v
```

Create a private key (default name will be privatekey.pem) using the algorithm "RSA4096" outputting the CSR to a file "mycsr.pem". Private key format will be OpenSSH
```
python3 ultimatecsr.py cli -ck -ka rsa4096 -o mycsr.pem -pkf OPENSSH
```


Create a private key (test_keypair.pem) using the ECC curve "SECP521R1" with encryption outputting the CSR to a file "mycsr.pem". Use PKCS1 formatting for private key
```
python3 ultimatecsr.py cli -ck test_keypair.pem -ka SECP521R1 -e -o mycsr.pem -pkf PKCS1
```

Create a CSR defining your already existing private key (great_privatekey.pem), outputting the CSR to a file called "mycsr.pem", using the SHA512 hashing algorithm

```
python3 ultimatecsr.py cli -p great_privatekey.pem -o mycsr.pem -ha SHA512
```

Create a CSR defining your already existing private key (great_privatekey.pem), outputting the CSR to a file called "mycsr.pem". Use short mode (only prompt common Distinguished Names). 

```
python3 ultimatecsr.py cli -p great_privatekey.pem -o mycsr.pem -m short
```


## Template Examples: 
** See the template folder to see example templates.
Create a CSR defining "example.json" as the template. By default, it will create a PEM csr in the "output/csr" folder.

```
python3 ultimatecsr.py template -t example.json
```

Create a CSR defining "test.json" as the template. By default, it will create a PEM csr in the "output/csr" folder. Output to CSR to standard out.

```
python3 ultimatecsr.py template -t test.json -o
```

Create a CSR defining "mytemplate.json" as the template. By default, it will create a PEM csr in the "output/csr" folder. Output to CSR to standard out. Enable more verbosity

```
python3 ultimatecsr.py template -t mytemplate.json -o -v
```