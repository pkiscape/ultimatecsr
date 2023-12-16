# Ultimate CSR ![alt text](https://pkiscape.com/img/favicon.png)
Ultimate CSR is a CLI tool that allows you to define more complex subjects and v3 extensions for your CSR. 

Let me know if you'd like to see any other extensions or fields!

## Usage
```
usage: ultimatecsr.py -p PRIVATEKEY -o FILENAME

X509 Certificate Signing Request Maker

optional arguments:
  -h, --help                   |   Display this help information
  -p PRIVATEKEY, --privatekey  |   Define your private key file in PEM format. If it's encrypted, it will ask for the password                 
  -o OUT, --out OUT            |   Define the CSR output filename
```

This tool allows you to:

- Define many subject fields such as Common Name, Email Address, UserID, Given Name, Title, Pseudonym and more!
- Request v3 extensions such as Key Usage, Extended Key Usage and Basic Constraints.

## Installation
Make sure Python Cryptography is up to date:

```
pip install --upgrade cryptography
```

Or, you can also use requirements.txt.
```
pip install -r requirements.txt
```


