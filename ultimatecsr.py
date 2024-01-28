#!/usr/bin/env python3

'''
=========================================
Ultimate CSR tool
=========================================

@version    5
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
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.backends import default_backend #For older versions of cryptography
from getpass import getpass

def load_private_key(privatekey):

	'''
	This function loads the passed private key. If it cannot load it, it asks for a password as the
	private key may be encrypted.
	'''

	with open(privatekey, "rb") as private_key_file:
		loaded_privatekey = private_key_file.read()

	try:
		loaded_privatekey = serialization.load_pem_private_key(loaded_privatekey, password=None, backend=default_backend())
		return loaded_privatekey
	except:
		print("Is your private key encrypted? If so:")
		password = getpass("Enter the password for the private key: ")

		try:
			loaded_privatekey = serialization.load_pem_private_key(loaded_privatekey,password=password.encode(),backend=default_backend())
			return loaded_privatekey
			print("Encrypted private key loaded")

		except ValueError:
			print("Incorrect password or unable to load the private key.")
			loaded_privatekey = "fail"
			return loaded_privatekey

def private_key_checker(filename):
	'''
	This function checks if you specified an existing private key to protect agianst 
	overwriting an already created private key.
	'''

	file_path = Path(filename)

	if file_path.is_file():
		print(f"The file '{filename}' exists. Specify a new name for the private key you want to create.")
		print(f"If '{filename}' is a private key you want to use, use the -p (--privatekey) parameter instead.")
		check = True

	else:
		check = False

	return check

def create_private_key(private_key_filename, encrypt):
	'''
	This creates a private key if none are defined
	'''

	print("Which algorithm would you like your private key to be?")
	print("1. RSA2048")
	print("2. RSA4096")
	print("3. SECP256R1")

	while True:
		algo_answer = input("Type 1, 2 or 3: ")

		if algo_answer == "1":
			private_key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
			break

		elif algo_answer == "2":
			private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
			break

		elif algo_answer == "3":
			private_key = ec.generate_private_key(ec.SECP256R1())
			break

		else:
			print("Please type in a 1, 2 or 3")

	if encrypt:
		with open(private_key_filename, "wb") as file:
			password = getpass("Enter the password you would like to use for the private key: ")
			enc_algo = serialization.BestAvailableEncryption(password.encode())
			private_key_bytes = private_key.private_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PrivateFormat.PKCS8,
				encryption_algorithm=enc_algo)
			file.write(private_key_bytes)

	else:
		with open(private_key_filename, "wb") as file:
			private_key_bytes = private_key.private_bytes(
				encoding=serialization.Encoding.PEM,
	            format=serialization.PrivateFormat.TraditionalOpenSSL,
	            encryption_algorithm=serialization.NoEncryption())
			file.write(private_key_bytes)

	return private_key		

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

	Todo: Maybe add these later?
	NameOID.SERIAL_NUMBER: Serial Number (SERIALNUMBER)	
	NameOID.BUSINESS_CATEGORY: Business Category or Industry Type
	NameOID.JURISDICTION_COUNTRY_NAME: Jurisdiction Country Name
	NameOID.JURISDICTION_STATE_OR_PROVINCE_NAME: Jurisdiction State or Province 
	'''
	
	print("==========Subject==========")
	print("Enter in each Subject field you require. Leave blank if not required." + "\n")
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
	print()

	subject_fields = []

	if cn:
		subject_fields.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
	if country:
		subject_fields.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))
	if state:
		subject_fields.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))
	if street:
		subject_fields.append(x509.NameAttribute(NameOID.STREET_ADDRESS, street))
	if postalcode:
		subject_fields.append(x509.NameAttribute(NameOID.POSTAL_CODE, postalcode))
	if locality:
		subject_fields.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))
	if orgname:
		subject_fields.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, orgname))
	if orgunit:
		subject_fields.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, orgunit))
	if dc:
		subject_fields.append(x509.NameAttribute(NameOID.DOMAIN_COMPONENT, dc))
	if email:
		subject_fields.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))
	if userid:
		subject_fields.append(x509.NameAttribute(NameOID.USER_ID, userid))
	if givenname:
		subject_fields.append(x509.NameAttribute(NameOID.GIVEN_NAME, givenname))
	if initials:
		subject_fields.append(x509.NameAttribute(NameOID.INITIALS, initials))	
	if surname:
		subject_fields.append(x509.NameAttribute(NameOID.SURNAME, surname))
	if title:
		subject_fields.append(x509.NameAttribute(NameOID.TITLE, title))
	if pseudonym:
		subject_fields.append(x509.NameAttribute(NameOID.PSEUDONYM, pseudonym))

	subject = x509.Name(subject_fields)

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
	print("==========X509 v3 Extensions==========" +"\n")
	print("Type in (y/n) or leave blank if not required." + "\n")

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

		if yes_no_input("Would you like to mark Extended Key Usage as critical? (y/n): "):
			eku_critical_choice = True

		else:
			eku_critical_choice = False

		extended_key_usage = x509.ExtendedKeyUsage(eku_choices)

		csr = csr.add_extension(extended_key_usage, critical=eku_critical_choice)

	return csr

def csr_builder(private_key):
	'''
	This builds the CSR object.
	'''

	#Add Subject
	subject = x509_subject()
	csr = x509.CertificateSigningRequestBuilder().subject_name(subject)

	#Pass CSR to x509_extensions(), add v3 extensions, return CSR
	if yes_no_input("Would you like to request x509v3 Extensions? (y/n):"):
		csr = x509_extensions(csr)
				
	#Sign CSR
	csr = csr.sign(private_key, hashes.SHA256())

	# Serialize CSR to PEM format
	csr_pem = csr.public_bytes(encoding=serialization.Encoding.PEM)

	# Convert bytes to a string
	csr_pem_str = csr_pem.decode()
	print("\n" +"Certificate signing request created:"+ "\n")
	print(csr_pem_str)

	return csr_pem


def main():

	'''
	The Ultimate CSR tool is a CLI tool that allows you to define many different subject types and x509v3 extensions.

	By: pkiscape.com

	Ref: https://cryptography.io/en/latest/x509/reference/

	'''

	argparse_main = argparse.ArgumentParser(description="X509 Certificate Signing Request Maker")

	argparse_group = argparse_main.add_mutually_exclusive_group(required=True)

	argparse_group.add_argument("-p","--privatekey",nargs="?",help="Define your existing private key.")
	argparse_group.add_argument("-k","--createkey",nargs="?", default="", help="Creates a private key for you. If no name is provided, it uses privatekey.pem")
	argparse_main.add_argument("-e","--encrypt", action="store_true", help="Encrypt the private key you create with -k (--createkey)")
	argparse_main.add_argument("-o","--out", help="Define the CSR output filename")
	args = argparse_main.parse_args()
		
	print("\n" + "Welcome to the Ultimate CSR tool! By: pkiscape.com" + "\n")

	if args.privatekey:
		private_key = load_private_key(args.privatekey)

	if args.createkey:
		check = private_key_checker(args.createkey)
		if check == False:
			private_key = create_private_key(args.createkey,args.encrypt)

	if args.createkey is None:
		check = private_key_checker("privatekey.pem")
		if check == False:
			private_key = create_private_key("privatekey.pem",args.encrypt)

	try:
		csr = csr_builder(private_key)

		if args.out:
			with open(args.out, "wb") as outfile:
				outfile.write(csr)
				print(f"CSR PEM written to {args.out}")

	except Exception as e:
		print("Stopping...")
		print(f"Exception thrown: {e}")

if __name__ == '__main__':
	main()