#!/usr/bin/env python3

'''
=========================================

Ultimate CSR tool

=========================================

@version	1 
@author     pkiscape.com
@link		https://github.com/pkiscape

'''

import argparse
import textwrap
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID
from getpass import getpass

def load_privatekey(privatekey):

	'''
	This function loads the passed private key. If it cannot load it, it asks for a password as the
	private key may be encrypted.
	
	'''

	with open(privatekey, "rb") as private_key_file:
		loaded_privatekey = private_key_file.read()

	try:
		loaded_privatekey = serialization.load_pem_private_key(loaded_privatekey,password=None)
		return loaded_privatekey
	except:
		print("Is your private key encrypted? If so:")
		password = getpass("Enter the password for the private key: ")

		try:
			loaded_privatekey = serialization.load_pem_private_key(loaded_privatekey,password=password.encode())
			return loaded_privatekey
			print("Encrypted private key loaded")


		except ValueError:
			print("Incorrect password or unable to load the private key.")
			loaded_privatekey = "fail"
			return loaded_privatekey
			


def x509_subject():

	'''
	
	This function defines the subjects for a given CSR. It returns the subject object

	Todo: Maybe add these later?

	NameOID.SERIAL_NUMBER: Serial Number (SERIALNUMBER)	
	NameOID.INITIALS: Initials of Given Names
	NameOID.BUSINESS_CATEGORY: Business Category or Industry Type
	NameOID.JURISDICTION_COUNTRY_NAME: Jurisdiction Country Name
	NameOID.JURISDICTION_STATE_OR_PROVINCE_NAME: Jurisdiction State or Province 

	'''
	print("==========Subject==========")
	print("Enter in Subject attributes. Leave blank if not required")
	print()
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
	surname = input(u"Surname: ") #NameOID.SURNAME: Surname or Family Name
	title = input(u"Title  or Honorific: ") #NameOID.TITLE: Title or Honorific
	pseudonym = input(u"Pseudonym: ") #NameOID.PSEUDONYM: Pseudonym or Alias
	print()

	subject_attributes = []

	if cn:
		subject_attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
	if country:
		subject_attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))
	if state:
		subject_attributes.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))
	if street:
		subject_attributes.append(x509.NameAttribute(NameOID.STREET_ADDRESS, street))
	if postalcode:
		subject_attributes.append(x509.NameAttribute(NameOID.POSTAL_CODE, postalcode))
	if locality:
		subject_attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))
	if orgname:
		subject_attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, orgname))
	if orgunit:
		subject_attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, orgunit))
	if dc:
		subject_attributes.append(x509.NameAttribute(NameOID.DOMAIN_COMPONENT, dc))
	if email:
		subject_attributes.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))
	if userid:
		subject_attributes.append(x509.NameAttribute(NameOID.USER_ID, userid))
	if givenname:
		subject_attributes.append(x509.NameAttribute(NameOID.GIVEN_NAME, givenname))
	if surname:
		subject_attributes.append(x509.NameAttribute(NameOID.SURNAME, surname))
	if title:
		subject_attributes.append(x509.NameAttribute(NameOID.TITLE, title))
	if pseudonym:
		subject_attributes.append(x509.NameAttribute(NameOID.PSEUDONYM, pseudonym))

	subject = x509.Name(subject_attributes)

	return subject


def x509_extensions(csr):

	'''
	Defines the X509 v3 extensions for the Certificate signing request. This function takes in the csr, then
	returns the csr back to the main function with the v3 extensions.

    Todo:Maybe add these later?
    SubjectAlternativeName: x509.SubjectAlternativeName (IP Addresses)
    NameConstraints: x509.NameConstraints
    IssuerAlternativeName: x509.IssuerAlternativeName
	SubjectInformationAccess: x509.SubjectInformationAccess
	InhibitAnyPolicy: x509.InhibitAnyPolicy
	CRLDistributionPoints: x509.CRLDistributionPoints
	CertificatePolicies: x509.CertificatePolicies
	AuthorityInformationAccess: x509.AuthorityInformationAccess
	PolicyConstraints: x509.PolicyConstraints

	'''
	print("==========X509 v3 Extensions==========")
	print()

	#SubjectAlternativeName: x509.SubjectAlternativeName
	yn_subject_alt_names = input("Would you like to add Subject Alternative Names? (y/n): ")

	if yn_subject_alt_names == 'y':
		subject_alt_names_values = []

		yn_san_dns = input("Would you like to add DNS names? (y/n): ")

		if yn_san_dns == "y":
			san_dns_int = input("How many? Enter in an integer: ")
			san_dns_int = int(san_dns_int)

			for dns_entry in range(0,san_dns_int):
				dns_name = input("Enter DNS entry: ")
				subject_alt_names_values.append(x509.DNSName(dns_name))
		
		subject_alternative_name = x509.SubjectAlternativeName(subject_alt_names_values)

		yn_san_critical = input("Would you like to mark Subject Alternative Name as critical? (y/n): ")

		if yn_san_critical == 'y':
			san_critical_choice = True

		else:
			san_critical_choice = False

		csr = csr.add_extension(subject_alternative_name, critical=san_critical_choice)


	#BasicConstraints: x509.BasicConstraints

	yn_basic_constraints = input("Would you like to request Basic Constraints? (y/n): ")
	
	if yn_basic_constraints == "y":
		yn_basic_constraints_crit = input("Would you like to mark Basic Constraints as critical? (y/n): ")

		if yn_basic_constraints_crit == "y":
			critical_choice = True

		else:
			critical_choice = False

		yn_ca = input("Would you like to add 'CA:TRUE'? (y/n): ")

		if yn_ca == "y":
			ca_choice = True
			yn_pathlength = input("Would you like to add a path length value? (y/n): ")

			if yn_pathlength == "y":
				pathlen_choice = input("Please enter an integer to be the path length: ")
				pathlen_choice = int(pathlen_choice)

			else:
				pathlen_choice = None
		else:
			ca_choice = False
			pathlen_choice = None


		basic_constraints = x509.BasicConstraints(ca=ca_choice, path_length=pathlen_choice)
		csr = csr.add_extension(basic_constraints, critical=critical_choice)

	#KeyUsage: x509.KeyUsage

	yn_key_usage = input("Would you like to request Key Usage values? (y/n): ")

	if yn_key_usage == "y":

		print("Type (y/n) for each possible value")

		yn_ku_ds = input("Digtal Signature: ")
		yn_ku_ke = input("Key Encipherment: ")
		yn_ku_cc = input("Content Commitment: ")
		yn_ku_de = input("Data Encipherment: ")
		yn_ku_ka = input("Key Agreement: ")
		yn_ku_kcs = input("Key Cert Sign: ")
		yn_ku_cs = input("CRL Sign: ")
		
		if yn_ku_ds == "y":
			ku_ds = True
		else:
			ku_ds = False

		if yn_ku_ke == "y":
			ku_ke = True
		else:
			ku_ke = False

		if yn_ku_cc == "y":
			ku_cc = True
		else:
			ku_cc = False

		if yn_ku_de == "y":
			ku_de = True
		else:
			ku_de = False

		# This must be done because Encipher/Decipher can only be added if Key Agreement is true 
		if yn_ku_ka == "y":
			ku_ka = True
			yn_ku_eo = input("Encipher Only: ")
			if yn_ku_eo == "y":
				ku_eo = True

			else:
				ku_eo = False
		
			yn_ku_do = input("Decipher Only: ")

			if yn_ku_do == "y":
				ku_do = True

			else:
				ku_do = False

		else:
			ku_ka = False
			ku_do = False
			ku_eo = False

		if yn_ku_kcs == "y":
			ku_kcs = True
		else:
			ku_kcs = False

		if yn_ku_cs == "y":
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

		yn_ku_critical = input("Would you like to mark Key Usage as critical? (y/n): ")

		if yn_ku_critical == 'y':
			ku_critical_choice = True

		else:
			ku_critical_choice = False

		csr = csr.add_extension(key_usage, critical=ku_critical_choice)


	#ExtendedKeyUsage: x509.ExtendedKeyUsage

	yn_ext_key_usage = input("Would you like to request Extended Key Usage values? (y/n): ")

	if yn_ext_key_usage == "y":

		eku_choices = []

		print("Type (y/n) for each extended key usage value")

		yn_eku_sa = input("TLS Server Auth: ")
		yn_eku_ca = input("TLS Client Auth: ")
		yn_eku_cs = input("Code Signing: ")
		yn_eku_ep = input("Email Protection: ")
		yn_eku_ts = input("Time Stamping: ")
		yn_eku_os = input("OCSP Signing: ")
		yn_eku_aku = input("Any Extended Key Usage: ")
		yn_eku_sl = input("Smartcard Login: ")
		yn_eku_kpk = input("Kerberos PKINIT KDC: ")
		yn_eku_ii = input("IPSEC IKE: ")
		yn_eku_ct = input("Certificate Transparency: ")

		if yn_eku_sa == "y":
			eku_choices.append(x509.oid.ExtendedKeyUsageOID.SERVER_AUTH)

		if yn_eku_ca == "y":
			eku_choices.append(x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH)

		if yn_eku_cs == "y":
			eku_choices.append(x509.oid.ExtendedKeyUsageOID.CODE_SIGNING)

		if yn_eku_ep == "y":
			eku_choices.append(x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION)

		if yn_eku_ts == "y":
			eku_choices.append(x509.oid.ExtendedKeyUsageOID.TIME_STAMPING)

		if yn_eku_os == "y":
			eku_choices.append(x509.oid.ExtendedKeyUsageOID.OCSP_SIGNING)

		if yn_eku_aku == "y":
			eku_choices.append(x509.oid.ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE)

		if yn_eku_sl == "y":
			eku_choices.append(x509.oid.ExtendedKeyUsageOID.SMARTCARD_LOGON)

		if yn_eku_kpk == "y":
			eku_choices.append(x509.oid.ExtendedKeyUsageOID.KERBEROS_PKINIT_KDC)

		if yn_eku_ii == "y":
			eku_choices.append(x509.oid.ExtendedKeyUsageOID.IPSEC_IKE)

		if yn_eku_ct == "y":
			eku_choices.append(x509.oid.ExtendedKeyUsageOID.CERTIFICATE_TRANSPARENCY)

		yn_eku_critical = input("Would you like to mark Key Usage as critical? (y/n): ")

		if yn_eku_critical == 'y':
			eku_critical_choice = True

		else:
			eku_critical_choice = False

		extended_key_usage = x509.ExtendedKeyUsage(eku_choices)

		csr = csr.add_extension(extended_key_usage, critical=eku_critical_choice)

	return csr



def main():

	'''
	The Ultimate CSR tool is a CLI tool that allows you to define many different subjects and v3 extensions.

	By Pkiscape.com

	Ref: https://cryptography.io/en/latest/x509/reference/

	'''

	argparse_main = argparse.ArgumentParser(description="X509 Certificate Signing Request Maker")
	argparse_main.add_argument("-p","--privatekey", help="Define your private key",required=True)
	argparse_main.add_argument("-o","--out", help="Define the CSR output filename")

	args = argparse_main.parse_args()

	#If certificate filename was provided
	if args.privatekey:
		try:
			print("\n" + "Welcome to the QuickCSR creator tool! By Pkiscape.com" + "\n")

			privatekey = load_privatekey(args.privatekey)

			if privatekey != "fail":
		
				#Add Subject
				subject = x509_subject()
				
				csr = x509.CertificateSigningRequestBuilder().subject_name(subject)

				#Pass CSR to x509_extensions(), add v3 extensions, return CSR
				csr = x509_extensions(csr)
				
				#Sign CSR
				csr = csr.sign(privatekey, hashes.SHA256())

				# Serialize CSR to PEM format
				csr_pem = csr.public_bytes(encoding=serialization.Encoding.PEM)

				# Convert bytes to a string
				csr_pem_str = csr_pem.decode()

				print()
				print("Certificate signing request created:")
				print()
				print(csr_pem_str)

				if args.out:
					with open(args.out, "wb") as outfile:
						outfile.write(csr_pem)
						print(f"CSR PEM written to {args.out}")
		
		except FileNotFoundError:
			print("Private key file could not be found.")


if __name__ == '__main__':
	main()
