#!/usr/bin/env python3

'''
=========================================
Ultimate CSR tool
=========================================

@version    8
@author     pkiscape.com
@link	    https://github.com/pkiscape

'''

import argparse
import textwrap
import ipaddress
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.backends import default_backend #For older versions of cryptography
from getpass import getpass

'''
Todo: Ideas

-Longer/shorter prompts
-Custom Subjects and more
-DER Private keys
-silent mode
-emojis
https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Name
'''

def load_private_key(private_key_filename,verbosity):

	'''
	This function loads the passed private key filename
	'''

	if verbosity:
		print(f"Attempting to load private key: {private_key_filename}")

	#Open Private key file
	with open(private_key_filename, "rb") as private_key_file_opened:
		loaded_privatekey = private_key_file_opened.read()

	#Checking for encryption in the private key
	if b"ENCRYPT" in loaded_privatekey:
		try:
			loaded_privatekey = load_enc_private_key(loaded_privatekey,verbosity,private_key_filename)
			return loaded_privatekey
		except Exception:
			print("Could not load the private key. Please make sure you entered the correct password and defined the correct file.")
			quit()
		
	else:
		try:
			loaded_privatekey = serialization.load_pem_private_key(loaded_privatekey, password=None, backend=default_backend())
			print(f"Loaded private key: '{private_key_filename}'")
			return loaded_privatekey

		except ValueError:
			try:
				if verbosity:
					print("Trying for the OpenSSH format. It could not load the format.")
				loaded_privatekey = serialization.load_ssh_private_key(loaded_privatekey,password=None,backend=default_backend())
				print(f"Loaded private key: '{private_key_filename}'")
				return loaded_privatekey

			except:
				# Last try will be to check if it's encrypted
				try:
					if verbosity:
						print("Could not load using any other method. Checking if it's encrypted")
					loaded_privatekey = load_enc_private_key(loaded_privatekey,verbosity,private_key_filename)
					return loaded_privatekey
				except:
					print("Could not load the private key. Please make sure you entered the correct password and defined the correct file.")
					quit()
		
		
def load_enc_private_key(enc_private_key,verbosity,private_key_filename):
	'''
	Attempted to load an encrypted private key
	'''
	if verbosity:
		print("It seems like the private key is encrypted")
	password = getpass("Enter the password for the private key: ")
	try:
		loaded_privatekey = serialization.load_pem_private_key(enc_private_key,password=password.encode(),backend=default_backend())
		print(f"Encrypted private key '{private_key_filename}'' loaded")
		return loaded_privatekey

	except ValueError:
		if verbosity:
			print("Trying for the OpenSSH format. It could not load the format.")
		try:
			loaded_privatekey = serialization.load_ssh_private_key(enc_private_key,password=password.encode(),backend=default_backend())
			print(f"Encrypted private key '{private_key_filename}' loaded")
			return loaded_privatekey
		except:
			if verbosity:
				print("Trying with password without encoding")
			loaded_privatekey = serialization.load_ssh_private_key(enc_private_key,password=password,backend=default_backend())
			print(f"Encrypted private key '{private_key_filename}' loaded")
			return loaded_privatekey


def private_key_checker(filename: str,verbosity):
	'''
	This function checks if you specified an existing private key to protect agianst 
	overwriting an already created private key.
	'''

	if verbosity:
		print(f"Checking if {filename} exists in running directory")

	file_path = Path(filename)

	if file_path.is_file():
		print(f"The file '{filename}' exists. Specify a new name for the private key you want to create.")
		print(f"If '{filename}' is a private key you want to use, use the -p (--privatekey) parameter instead.\n")
		check = True
		quit()

	else:
		check = False
		if verbosity:
			print(f"{filename} doesn't exist, continuing...")

	return check

def create_private_key(private_key_filename: str, encrypt, key_algorithm,verbosity,private_key_format):
	'''
	Creates a private key. 
	Default algorithm: SECP384R1
	
	Valid Algorithms: "RSA2048", "RSA4096", "SECP256R1", "SECP384R1", "SECP521R1", "SECP256K1"
	'''

	if verbosity:
		print(f"Creating Private Key with name {private_key_filename} with the {key_algorithm} algorithm. Encrypt: {encrypt}. Private Key Format: {private_key_format}")

	if key_algorithm == "RSA2048":
		private_key = rsa.generate_private_key(public_exponent=65537,key_size=2048,backend=default_backend())

	if key_algorithm == "RSA4096":
		private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096,backend=default_backend())

	if key_algorithm == "SECP256R1":
		private_key = ec.generate_private_key(ec.SECP256R1(),backend=default_backend())

	if key_algorithm == "SECP384R1":
		private_key = ec.generate_private_key(ec.SECP384R1(),backend=default_backend())

	if key_algorithm == "SECP521R1":
		private_key = ec.generate_private_key(ec.SECP521R1(),backend=default_backend())

	if key_algorithm == "SECP256K1":
		private_key = ec.generate_private_key(ec.SECP256K1(), backend=default_backend())


	private_key_format_full = "serialization.PrivateFormat."+ private_key_format

	private_key_format_mapping = {
	    "PKCS1": serialization.PrivateFormat.TraditionalOpenSSL,
	    "PKCS8": serialization.PrivateFormat.PKCS8,
	    "OPENSSH": serialization.PrivateFormat.OpenSSH
	}
	
	private_key_format_enum = private_key_format_mapping.get(private_key_format)

	if encrypt:
		# If the private key format is OPENSSH, bcrypt is required (pip install bcrypt)
		with open(private_key_filename, "wb") as file:
			if verbosity:
				print("Encrypting privatekey with 'BestAvailableEncryption'")
			password = getpass("Enter the password you would like to use for the private key: ")
			enc_algo = serialization.BestAvailableEncryption(password.encode())

			try:
				private_key_bytes = private_key.private_bytes(
					encoding=serialization.Encoding.PEM,
					format=private_key_format_enum,
					encryption_algorithm=enc_algo)
				file.write(private_key_bytes)
			except Exception as unsupported_algo_exception:
				if "bcrypt" in str(unsupported_algo_exception):
					print(f"Error: {unsupported_algo_exception}. The Python Cryptography library uses another library called bcrypt for encrypting OpenSSH keys")
					print("For installation, please check out: https://pypi.org/project/bcrypt/")
					quit()

	else:
		with open(private_key_filename, "wb") as file:
			private_key_bytes = private_key.private_bytes(
				encoding=serialization.Encoding.PEM,
				format=private_key_format_enum,
				encryption_algorithm=serialization.NoEncryption())
			file.write(private_key_bytes)

	print(f"Created Private Key: '{private_key_filename}' using {key_algorithm}. Format: PEM ({private_key_format})")
	return private_key		

def hash_builder(hash_algorithm):
	'''
	Chooses the hash function based on the one that was provided

	Allowed hashes:
    hashes.SHA224,
    hashes.SHA256,
    hashes.SHA384,
    hashes.SHA512,
    hashes.SHA3_224,
    hashes.SHA3_256,
    hashes.SHA3_384,
    hashes.SHA3_512,
	'''

	if hash_algorithm == "SHA224":
		hash_function_obj = hashes.SHA224()

	if hash_algorithm == "SHA256":
		hash_function_obj = hashes.SHA256()

	if hash_algorithm == "SHA384":
		hash_function_obj = hashes.SHA384()

	if hash_algorithm == "SHA512":
		hash_function_obj = hashes.SHA512()

	if hash_algorithm == "SHA3_224":
		hash_function_obj = hashes.SHA3_224()

	if hash_algorithm == "SHA3_256":
		hash_function_obj = hashes.SHA3_256()

	if hash_algorithm == "SHA3_384":
		hash_function_obj = hashes.SHA3_384()

	if hash_algorithm == "SHA3_512":
		hash_function_obj = hashes.SHA3_512()

	return hash_function_obj

def yes_no_input(prompt: str):
	'''
	Since there are a lot of yes/no questions, this function helps reduce lines!
	'''
	user_input = input(prompt).lower()
	if user_input == "y":
		return True

	if user_input == "n":
		return False

	else:
		#No user input means "no"
		return False

def integer_input(prompt):
	'''
	Makes sure that the input provided is an integer
	'''
	while True:
		try:
			user_input = input(prompt)
			integer_value = int(user_input)
			return integer_value
		except ValueError:
			print("Please enter in an integer.")

def x509_subject():

	'''
	This function defines the distinguished name for a given CSR. It returns the subject object.
	'''
	
	print("\n==========Distinguished Name==========\nEnter in each type you require. Leave blank if not required.\n")

	cn = input(u"Common Name: ") #NameOID.COMMON_NAME: Common Name
	country = input(u"Country Name (2 letter code): ") #NameOID.COUNTRY_NAME: Country Name
	state = input(u"State or Province Name (full name): ") #NameOID.STATE_OR_PROVINCE_NAME: State or Province Name
	street = input(u"Street Address: ") #NameOID.STREET_ADDRESS: Street Address
	postalcode = input(u"Postal Code: ") #NameOID.POSTAL_CODE: Postal Code 
	locality = input(u"Locality Name: ") #NameOID.LOCALITY_NAME: Locality Name
	orgname = input(u"Organization Name: ") #NameOID.ORGANIZATION_NAME: Organization Name
	orgunit = input(u"Organizational Unit Name: ") #NameOID.ORGANIZATIONAL_UNIT_NAME: Organizational Unit Name
	dc = input(u"Domain Component: ") #NameOID.DOMAIN_COMPONENT
	email = input(u"Email Address: ") #NameOID.EMAIL_ADDRESS: Email Address
	userid = input(u"UserID: ") #NameOID.USER_ID
	givenname = input(u"Given Name: ") #NameOID.GIVEN_NAME: Given Name or First Name
	initials = input(u"Initials: ") #NameOID.INITIALS: Initials of Given Names 
	surname = input(u"Surname: ") #NameOID.SURNAME: Surname or Family Name
	title = input(u"Title or Honorific: ") #NameOID.TITLE: Title or Honorific
	pseudonym = input(u"Pseudonym: ") #NameOID.PSEUDONYM: Pseudonym or Alias
	unstructured = input(u"Unstructured Name: ") #NameOID.UNSTRUCTURED_NAME: 1.2.840.113549.1.9.2

	dn_types = []

	if cn:
		dn_types.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
	if country:
		dn_types.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))
	if state:
		dn_types.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))
	if street:
		dn_types.append(x509.NameAttribute(NameOID.STREET_ADDRESS, street))
	if postalcode:
		dn_types.append(x509.NameAttribute(NameOID.POSTAL_CODE, postalcode))
	if locality:
		dn_types.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))
	if orgname:
		dn_types.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, orgname))
	if orgunit:
		dn_types.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, orgunit))
	if dc:
		dn_types.append(x509.NameAttribute(NameOID.DOMAIN_COMPONENT, dc))
	if email:
		dn_types.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))
	if userid:
		dn_types.append(x509.NameAttribute(NameOID.USER_ID, userid))
	if givenname:
		dn_types.append(x509.NameAttribute(NameOID.GIVEN_NAME, givenname))
	if initials:
		dn_types.append(x509.NameAttribute(NameOID.INITIALS, initials))	
	if surname:
		dn_types.append(x509.NameAttribute(NameOID.SURNAME, surname))
	if title:
		dn_types.append(x509.NameAttribute(NameOID.TITLE, title))
	if pseudonym:
		dn_types.append(x509.NameAttribute(NameOID.PSEUDONYM, pseudonym))
	if unstructured:
		dn_types.append(x509.NameAttribute(NameOID.UNSTRUCTURED_NAME, unstructured))

	subject = x509.Name(dn_types)

	return subject

def x509_extensions(csr):

	'''
	Defines the X509 v3 extensions for the Certificate signing request. This function takes in the csr, then
	returns the csr back to the main function with the v3 extensions.

	Todo:Maybe add these later?
	NameConstraints: x509.NameConstraints
	IssuerAlternativeName: x509.IssuerAlternativeName
	SubjectInformationAccess: x509.SubjectInformationAccess
	InhibitAnyPolicy: x509.InhibitAnyPolicy
	CRLDistributionPoints: x509.CRLDistributionPoints
	CertificatePolicies: x509.CertificatePolicies
	AuthorityInformationAccess: x509.AuthorityInformationAccess
	PolicyConstraints: x509.PolicyConstraints
	'''
	print("\n==========X509 v3 Extensions==========\nType in (y/n) or leave blank if not required.\n")

	#SubjectAlternativeName: x509.SubjectAlternativeName
	if yes_no_input("Would you like to add Subject Alternative Names? (y/n): "):
		subject_alt_names_values = []

		#DNS Names
		if yes_no_input("Would you like to add DNS names? (y/n): "):
			san_dns_int = integer_input("How many? Enter in an integer: ")
			for dns_entry in range(san_dns_int):
				dns_name = input("Enter DNS entry: ")
				subject_alt_names_values.append(x509.DNSName(dns_name))
		
		#IPv4 Addresses
		if yes_no_input("Would you like to add IPv4 Addresses? (y/n): "):
			san_ip_int = integer_input("How many? Enter in an integer: ")
			for ip_entry in range(san_ip_int):
				while True:
					try:
						ip = input("Enter IPv4 Address: ")
						ip = ipaddress.IPv4Address(ip)
						subject_alt_names_values.append(x509.IPAddress(ip))
						break

					except:
						print("Please enter in a valid IPv4 Address. (Example: 192.168.1.1)")
		subject_alternative_name = x509.SubjectAlternativeName(subject_alt_names_values)

		if yes_no_input("Would you like to mark Subject Alternative Name as critical? (y/n): "):
			san_critical_choice = True

		else:
			san_critical_choice = False

		csr = csr.add_extension(subject_alternative_name, critical=san_critical_choice)

	#BasicConstraints: x509.BasicConstraints
	if yes_no_input("Would you like to request Basic Constraints? (y/n): "):
		if yes_no_input("Would you like to mark Basic Constraints as critical? (y/n): "):
			critical_choice = True

		else:
			critical_choice = False

		if yes_no_input("Would you like to add 'CA:TRUE'? (y/n): "):
			ca_choice = True
			if yes_no_input("Would you like to add a path length value? (y/n): "):
				pathlen_choice = integer_input("Please enter an integer to be the path length: ")

			else:
				pathlen_choice = None
		else:
			ca_choice = False
			pathlen_choice = None

		basic_constraints = x509.BasicConstraints(ca=ca_choice, path_length=pathlen_choice)
		csr = csr.add_extension(basic_constraints, critical=critical_choice)

	#KeyUsage: x509.KeyUsage
	if yes_no_input("Would you like to request Key Usage values? (y/n): "):
		print("Type (y/n) for each possible value.")
		
		if yes_no_input("Digital Signature: "):
			ku_ds = True
		else:
			ku_ds = False

		if yes_no_input("Key Encipherment: "):
			ku_ke = True
		else:
			ku_ke = False

		if yes_no_input("Content Commitment(Non Repudiation): "):
			ku_cc = True
		else:
			ku_cc = False

		if yes_no_input("Data Encipherment: "):
			ku_de = True
		else:
			ku_de = False

		# This must be done because Encipher/Decipher can only be added if Key Agreement is true 
		if yes_no_input("Key Agreement: "):
			ku_ka = True
			if yes_no_input("Encipher Only: "):
				ku_eo = True
			else:
				ku_eo = False
		
			if yes_no_input("Decipher Only: "):
				ku_do = True

			else:
				ku_do = False
		else:
			ku_ka = False
			ku_do = False
			ku_eo = False

		if yes_no_input("Key Cert Sign(Certificate Sign): "):
			ku_kcs = True
		else:
			ku_kcs = False

		if yes_no_input("CRL Sign: "):
			ku_cs = True
		else:
			ku_cs = False

		#Create KU Object
		key_usage = x509.KeyUsage(
			digital_signature= ku_ds,
			key_encipherment=ku_ke,
			content_commitment=ku_cc,
			data_encipherment=ku_de,
			key_agreement=ku_ka,
			key_cert_sign=ku_kcs,
			crl_sign=ku_cs,
			encipher_only = ku_eo,
			decipher_only=ku_do)

		if yes_no_input("Would you like to mark Key Usage as critical? (y/n): "):
			ku_critical_choice = True

		else:
			ku_critical_choice = False

		csr = csr.add_extension(key_usage, critical=ku_critical_choice)

	#ExtendedKeyUsage: x509.ExtendedKeyUsage
	if yes_no_input("Would you like to request Extended Key Usage values? (y/n): "):

		eku_choices = []

		print("Type (y/n) for each extended key usage value")

		if yes_no_input("TLS Server Auth: "):
			eku_choices.append(x509.oid.ExtendedKeyUsageOID.SERVER_AUTH)

		if yes_no_input("TLS Client Auth: "):
			eku_choices.append(x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH)

		if yes_no_input("Code Signing: "):
			eku_choices.append(x509.oid.ExtendedKeyUsageOID.CODE_SIGNING)

		if yes_no_input("Email Protection: "):
			eku_choices.append(x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION)

		if yes_no_input("Time Stamping: "):
			eku_choices.append(x509.oid.ExtendedKeyUsageOID.TIME_STAMPING)

		if yes_no_input("OCSP Signing: "):
			eku_choices.append(x509.oid.ExtendedKeyUsageOID.OCSP_SIGNING)

		if yes_no_input("Any Extended Key Usage: "):
			eku_choices.append(x509.oid.ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE)

		if yes_no_input("Smartcard Login (Microsoft Smartcard Login): "):
			eku_choices.append(x509.oid.ExtendedKeyUsageOID.SMARTCARD_LOGON)

		if yes_no_input("Kerberos PKINIT KDC (Signing KDC Response):  "):
			eku_choices.append(x509.oid.ExtendedKeyUsageOID.KERBEROS_PKINIT_KDC)

		if yes_no_input("IPSEC IKE (ipsec Internet Key Exchange): "):
			eku_choices.append(x509.oid.ExtendedKeyUsageOID.IPSEC_IKE)

		if yes_no_input("Certificate Transparency (CT Precertificate Signer): "):
			eku_choices.append(x509.oid.ExtendedKeyUsageOID.CERTIFICATE_TRANSPARENCY)

		if yes_no_input("SSH Client (secureShellClient): "):
			ssh_client_oid = x509.ObjectIdentifier("1.3.6.1.5.5.7.3.21")
			eku_choices.append(ssh_client_oid)

		if yes_no_input("SSH Server (secureShellServer): "):
			ssh_server_oid = x509.ObjectIdentifier("1.3.6.1.5.5.7.3.22")
			eku_choices.append(ssh_server_oid)

		# Custom OIDs for Extended Key Usage
		if yes_no_input("Would you like to request custom Extended Key Usage values (OIDs)? (y/n):"):
			custom_oids_amount = integer_input("How many? Enter in an integer: ")
			for custom_oid in range(custom_oids_amount):
				while True:
					try:
						oid = input("Enter in your OID: ")
						built_oid = x509.ObjectIdentifier(oid)
						break

					except ValueError:
						print("Enter in a valid OID")
				
				eku_choices.append(built_oid)

		if yes_no_input("Would you like to mark Extended Key Usage as critical? (y/n): "):
			eku_critical_choice = True

		else:
			eku_critical_choice = False

		extended_key_usage = x509.ExtendedKeyUsage(eku_choices)

		csr = csr.add_extension(extended_key_usage, critical=eku_critical_choice)

	return csr

def csr_builder(private_key,hash_algorithm,verbosity):
	'''
	This builds the CSR object.
	'''

	#Add Distinguished Name
	subject = x509_subject()
	csr = x509.CertificateSigningRequestBuilder().subject_name(subject)

	#Pass CSR to x509_extensions(), add v3 extensions, return CSR
	if yes_no_input("Would you like to request x509v3 Extensions? (y/n):"):
		csr = x509_extensions(csr)
				
	#Build hash object
	if verbosity:
		print(f"Selected Hash function {hash_algorithm}")
	hash_function_obj = hash_builder(hash_algorithm)

	#Sign CSR
	if verbosity:
		print("Signing CSR with private key")
	csr = csr.sign(private_key,hash_function_obj, backend=default_backend())

	# Serialize CSR to PEM format
	if verbosity:
		print("Serializing CSR to PEM format")
	csr_pem = csr.public_bytes(encoding=serialization.Encoding.PEM)

	# Convert bytes to a string
	csr_pem_str = csr_pem.decode()
	print(f"\nCertificate signing request created:\n\n{csr_pem_str}")

	return csr_pem

def main():

	'''
	The Ultimate CSR tool is an interactive CLI tool that allows you to define many different distinguished name types and x509v3 extensions.

	By: pkiscape.com
	'''

	argparse_main = argparse.ArgumentParser(description="X.509 Certificate Signing Request Maker")

	argparse_group = argparse_main.add_mutually_exclusive_group(required=True)

	argparse_group.add_argument("-p","--private-key",nargs="?",help="Define your existing private key.")
	argparse_group.add_argument("-ck","--create-key",nargs="?", default="",help="Creates a private key for you. If no name is provided, it uses 'privatekey.pem'.")
	argparse_main.add_argument("-pkf","--private-key-format",type=str.upper, choices=["PKCS1","PKCS8","OPENSSH"], default="PKCS8",
		help="When creating a private key with --create-key, choose the format it gets created. Default (PKCS8)")
	argparse_main.add_argument("-ka", "--key-algorithm", type=str.upper, choices=["RSA2048", "RSA4096", "SECP256R1", "SECP384R1","SECP521R1","SECP256K1"], default="SECP384R1",
		help="Define the algorithm and key size of the private key you define with --create-key. Default (SECP384R1).")
	argparse_main.add_argument("-e","--encrypt", action="store_true", help="Encrypt the private key you create with --create-key")
	argparse_main.add_argument("-o","--out", help="Define the CSR output filename")
	argparse_main.add_argument("-ha","--hash-algorithm", type=str.upper, default="SHA256",
		choices=["SHA224","SHA256","SHA384","SHA512","SHA3_224","SHA3_256","SHA3_384","SHA3_512"],help="Define the hashing algorithm (Signature Algorithm). Default(SHA256).")
	argparse_main.add_argument("-v","--verbose",action="store_true",help="Enable verbosity (more wordiness)")
	args = argparse_main.parse_args()
		
	print(f"\nWelcome to the Ultimate CSR tool! By: pkiscape.com\n")

	if args.private_key:
		try:
			private_key = load_private_key(
				private_key_filename=args.private_key,
				verbosity=args.verbose)

		except FileNotFoundError:
			print(f"Defined private key file '{args.private_key}' not found.")
			quit()

	if args.create_key:
		check = private_key_checker(filename=args.create_key,verbosity=args.verbose)
		if check == False:
			private_key = create_private_key(
				private_key_filename=args.create_key,
				encrypt=args.encrypt,
				key_algorithm=args.key_algorithm,
				verbosity=args.verbose,
				private_key_format=args.private_key_format)

	if args.create_key is None:
		check = private_key_checker(filename="privatekey.pem",verbosity=args.verbose)
		if check == False:
			private_key = create_private_key(
				private_key_filename="privatekey.pem",
				encrypt=args.encrypt,
				key_algorithm=args.key_algorithm,
				verbosity=args.verbose,
				private_key_format=args.private_key_format)

	try:
		csr = csr_builder(
			private_key=private_key,
			hash_algorithm=args.hash_algorithm,
			verbosity=args.verbose)

		if args.out:
			with open(args.out, "wb") as outfile:
				outfile.write(csr)
				print(f"CSR PEM written to '{args.out}'")

	except Exception as e:
		print(f"Exception thrown: {e}")

if __name__ == '__main__':
	main()
