#!/usr/bin/env python3

"""
=========================================
Ultimate CSR tool - Templates
=========================================

@author    pkiscape.com
@link      https://github.com/pkiscape

"""

import json
import ipaddress
import sys
import logging
from random import choices
from string import ascii_lowercase
from pathlib import Path
from getpass import getpass
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import AttributeOID, NameOID
from cryptography.hazmat.backends import default_backend  # For older versions of cryptography

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Path Constants
PROJECT_ROOT = Path(__file__).resolve().parents[2]
TEMPLATES_DIR = PROJECT_ROOT / "templates"
PRIVATE_KEYS_DIR = PROJECT_ROOT / "output" / "private_keys"
CSR_DIR = PROJECT_ROOT / "output" / "csr"


def template_checker(filename, verbosity: bool) -> bool:
    """Determines if the template is formatted correctly"""

    check_result = False
    title_not_found = False

    try:
        with open(filename, "r",encoding="utf-8") as json_file:
            opened_json_file = json.load(json_file)

    except json.decoder.JSONDecodeError as json_decode_error:
        logger.error(json_decode_error)
        return False

    else:
        # Checks for required titles
        valid_template_titles = ["private_key_config", "x509_subject"]

        for title in valid_template_titles:
            if title not in opened_json_file:
                logger.warning(f"Required element '{title}' not found in template.")
                title_not_found = True

    if title_not_found is False:
        check_result = True

    return check_result


class PrivateKeyHandler:
    """
    Handles Private Key functions
    """
    def __init__(self, template):
        self.private_key_output = self.build_private_key_config(template)

    def build_private_key_config(self, template: dict) -> object:
        """Sets the private key configuration for the CSR. Creates or uses existing private key"""

        def private_key_checker(filename: str) -> bool:
            """
            Runs when private_key_overwrite_protection: True
            This function checks if you specified an existing private key to protect agianst
            overwriting an already created private key.
            """

            logger.info(f"Checking if {filename} exists...")

            file_path = PRIVATE_KEYS_DIR / filename

            if file_path.is_file():
                logger.warning(
                    f"The file '{filename}' exists. Choose a different filename to avoid overwriting"
                )
                logger.info(
                    f"If '{filename}' is a private key you want to use, define it in existing_private_key_config"
                )
                return True

            logger.info(f"Private key '{filename}' does not exist. Proceeding with key creation.")
            return False

        def create_private_key(filename: str, key_settings: dict) -> object:
            """
            Creates a private key.
            Default algorithm: SECP384R1
            Valid Algorithms: "RSA2048", "RSA4096", "SECP256R1", "SECP384R1", "SECP521R1", "SECP256K1"
            """

            # Get algorithm settings
            key_algorithm = key_settings.get(
                "key_algorithm", "SECP384R1"
            )  # SECP384R1 if none are defined
            encrypt = key_settings.get("encrypt", False)  # False if none are defined
            private_key_format = key_settings.get(
                "private_key_format", "PKCS8"
            )  # PKCS8 if none are defined

            logger.info(
                f"Creating Private Key with name {filename} with the {key_algorithm} algorithm. Encrypt: {encrypt}. Private Key Format: {private_key_format}"
            )

            # Select Key Algorithm and its size
            if key_algorithm == "RSA2048":
                private_key = rsa.generate_private_key(
                    public_exponent=65537, key_size=2048, backend=default_backend()
                )

            elif key_algorithm == "RSA4096":
                private_key = rsa.generate_private_key(
                    public_exponent=65537, key_size=4096, backend=default_backend()
                )

            elif key_algorithm == "SECP256R1":
                private_key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())

            elif key_algorithm == "SECP384R1":
                private_key = ec.generate_private_key(ec.SECP384R1(), backend=default_backend())

            elif key_algorithm == "SECP521R1":
                private_key = ec.generate_private_key(ec.SECP521R1(), backend=default_backend())

            elif key_algorithm == "SECP256K1":
                private_key = ec.generate_private_key(ec.SECP256K1(), backend=default_backend())

            else:
                # Sets SECP384R1 as default if none are chosen
                private_key = ec.generate_private_key(ec.SECP384R1(), backend=default_backend())

            # Select Private Key Format
            private_key_format_mapping = {
                "PKCS1": serialization.PrivateFormat.TraditionalOpenSSL,
                "PKCS8": serialization.PrivateFormat.PKCS8,
                "OPENSSH": serialization.PrivateFormat.OpenSSH,
            }

            # PKCS8 chosen as default if none are chosen
            private_key_format_enum = private_key_format_mapping.get(
                private_key_format, serialization.PrivateFormat.PKCS8
            )

            output_path = PRIVATE_KEYS_DIR / filename

            # Ensure the directory exists
            output_path.parent.mkdir(parents=True, exist_ok=True)

            if encrypt:
                logger.info("Encrypting privatekey with 'BestAvailableEncryption'")
                # If the private key format is OPENSSH, bcrypt is required (pip install bcrypt)
                with open(output_path, "wb") as file:
                    password = getpass(
                        "Enter the password you would like to use for the private key: "
                    )
                    enc_algo = serialization.BestAvailableEncryption(password.encode())

                    try:
                        private_key_bytes = private_key.private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=private_key_format_enum,
                            encryption_algorithm=enc_algo,
                        )
                        file.write(private_key_bytes)
                    except Exception as unsupported_algo_exception:
                        if "bcrypt" in str(unsupported_algo_exception):
                            logger.warning(
                                f"Error: {unsupported_algo_exception}. The Python Cryptography library uses another library called bcrypt for encrypting OpenSSH keys"
                            )
                            logger.info(
                                "For installation, please check out: https://pypi.org/project/bcrypt/"
                            )
                            sys.exit(1)

            else:
                with open(output_path, "wb") as file:
                    private_key_bytes = private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=private_key_format_enum,
                        encryption_algorithm=serialization.NoEncryption(),
                    )
                    file.write(private_key_bytes)

            logger.info(
                f"Created Private Key: '{output_path}' using {key_algorithm}. Format: PEM ({private_key_format})"
            )

            return private_key

        def load_enc_private_key(enc_private_key: object, filename: str) -> object:
            """
            Load an encrypted private key and attempt to decrypt
            """
            logger.info("It seems like the private key is encrypted")
            password = getpass("Enter the password for the private key: ")

            try:
                loaded_privatekey = serialization.load_pem_private_key(
                    enc_private_key, password=password.encode(), backend=default_backend()
                )
                logger.info(f"Encrypted private key '{filename}'' loaded")
                return loaded_privatekey

            except ValueError:
                logger.info("Trying for the OpenSSH format. It could not load the format.")
                try:
                    loaded_privatekey = serialization.load_ssh_private_key(
                        enc_private_key, password=password.encode(), backend=default_backend()
                    )
                    logger.info(f"Encrypted private key '{filename}' loaded")
                    return loaded_privatekey
                except:
                    logger.info("Trying with password without encoding")
                    loaded_privatekey = serialization.load_ssh_private_key(
                        enc_private_key, password=password, backend=default_backend()
                    )
                    logger.info(f"Encrypted private key '{filename}' loaded")
                    return loaded_privatekey

        def load_private_key(filename: str) -> object:
            """
            Loads the passed private key filename
            """

            logger.info(f"Attempting to load private key: {filename}")

            output_path = PRIVATE_KEYS_DIR / filename
            output_path.parent.mkdir(parents=True, exist_ok=True)

            # Open Private key file
            with open(output_path, "rb") as private_key_file_opened:
                loaded_privatekey = private_key_file_opened.read()
                logger.debug(f"Opened file {filename}")

            # Checking for encryption in the private key
            logger.debug(f"Checking for encryption in the private key: {filename}")
            if b"ENCRYPT" in loaded_privatekey:
                try:
                    loaded_privatekey = load_enc_private_key(
                        enc_private_key=loaded_privatekey, filename=filename
                    )
                    logger.info(f"Successfully loaded encrypted private key: {filename}")
                    return loaded_privatekey
                except Exception:
                    logger.warning(
                        "Could not load the private key. Make sure you entered the correct password and defined the correct file."
                    )
                    sys.exit(1)

            else:
                logger.debug(f"No encryption found for private key: {filename}")
                try:
                    loaded_privatekey = serialization.load_pem_private_key(
                        loaded_privatekey, password=None, backend=default_backend()
                    )
                    logger.info(f"Loaded private key: '{filename}'")
                    return loaded_privatekey

                except ValueError:
                    try:
                        logger.info(
                            "Trying for the OpenSSH format. It could not PKCS8 / PKCS1 format."
                        )
                        loaded_privatekey = serialization.load_ssh_private_key(
                            loaded_privatekey, password=None, backend=default_backend()
                        )
                        print(f"Loaded private key: '{filename}'")
                        return loaded_privatekey

                    except:
                        # Last try will be to check if it's encrypted
                        try:
                            logger.info(
                                "Could not load using any other method. Checking if it's encrypted."
                            )
                            loaded_privatekey = load_enc_private_key(
                                enc_private_key=loaded_privatekey, filename=filename
                            )
                            return loaded_privatekey
                        except Exception:
                            logger.warning(
                                "Could not load the private key. Make sure you entered the correct password and defined the correct file."
                            )
                            sys.exit(1)

        logger.info("Building Private Key Configuration")

        pkc_root = template.get("private_key_config")

        random_name = ""

        if pkc_root["create_new_private_key"] is True:
            new_private_key_settings = pkc_root["new_private_key_config"]

            if new_private_key_settings["random_private_key_name"] is True:
                random_name = "".join(choices(ascii_lowercase, k=12))
                key_filename = f"{random_name}.pem"

            else:
                key_filename = new_private_key_settings.get("private_key_filename")

            #key_filename = private_key_dir + key_filename

            if pkc_root.get("private_key_overwrite_protection"):
                logger.info(f"Checking if {key_filename} already exists")
                if private_key_checker(filename=key_filename):
                    sys.exit(1)

            logger.debug("Running Create Private Key Function")
            private_key = create_private_key(
                filename=key_filename, key_settings=new_private_key_settings
            )

        # Use existing private key
        elif pkc_root["create_new_private_key"] is False:
            key_filename = pkc_root["existing_private_key_config"]["private_key_filename"]

            try:
                private_key = load_private_key(filename=key_filename)

            except FileNotFoundError:
                logger.warning(f"Defined private key file '{args.private_key}' not found.")
                sys.exit(1)

        else:
            logger.warning("Set 'create_new_private_key' to be true or false (no quotes)")
            sys.exit(1)

        return [private_key, random_name]

class CSRBundle:

    """
    Builds a CSR Bundle based on template
    A bundle contains multiple objects, including the CSR PEM and Private Key Config
    """

    def __init__(self, template):
        # Loaded Private Key
        logger.debug("Initiating private_key_config build")
        self.priv_key = PrivateKeyHandler(template)

        private_key = self.priv_key.private_key_output[0]
        random_name = self.priv_key.private_key_output[1]

        # Create X509 Subject
        logger.debug("Initiating x509_subject build")
        self.x509_subject = self.build_x509_subject(template)

        # Create CSR Object
        logger.debug("Creating CSR Object with Subject")
        self.tbs_csr = x509.CertificateSigningRequestBuilder().subject_name(self.x509_subject)

        # Add X509v3 Extensions
        logger.debug("Initiating x509_extensions build")
        self.tbs_csr = self.build_x509_extensions(template=template, csr=self.tbs_csr)

        # Signing Hash Algorithm
        logger.debug("Initiating signing_hash_algorithm build")
        self.signing_hash_algorithm = self.build_signing_hash_algorithm(template)

        # Challenge Password
        logger.debug("Initiating challenge_password build")
        self.challenge_password = self.build_challenge_password(template)

        if self.challenge_password:
            self.tbs_csr = self.tbs_csr.add_attribute(
                AttributeOID.CHALLENGE_PASSWORD, self.challenge_password
            )

        # Sign CSR using private key, signing hash function
        logger.debug("Initiating build_csr")
        self.built_csr = self.build_csr(
            csr=self.tbs_csr,
            private_key=private_key,
            signing_hash_algorithm=self.signing_hash_algorithm,
        )

        # Setup the output and create file if requested
        logger.debug("Initiating csr output build")
        self.csr_output = self.build_csr_output(
            template=template, csr=self.built_csr, random_name=random_name
        )

    def build_x509_subject(self, template: dict) -> x509.Name:
        """Defines the distinguished name for a given CSR. It returns the subject object."""

        logger.info(
            "Building Distinguished Name. They are single-valued relative distinguished names (RDNs) based on rfc4514"
        )

        dn_root = template.get("x509_subject")
        rdn_list = []

        def add_if_present(name_oid, key):
            """Adds Subject if present"""
            value = dn_root.get(key)
            if value:
                rdn_list.append(x509.NameAttribute(name_oid, value))

        add_if_present(NameOID.SERIAL_NUMBER, "serial_number")
        add_if_present(NameOID.COMMON_NAME, "common_name")
        add_if_present(NameOID.COUNTRY_NAME, "country_name (2 letter code)")
        add_if_present(NameOID.STATE_OR_PROVINCE_NAME, "state_or_province_name (full name)")
        add_if_present(NameOID.STREET_ADDRESS, "street_address")
        add_if_present(NameOID.POSTAL_CODE, "postal_code")
        add_if_present(NameOID.LOCALITY_NAME, "locality_name")
        add_if_present(NameOID.ORGANIZATION_NAME, "organization_name")
        add_if_present(NameOID.ORGANIZATIONAL_UNIT_NAME, "organizational_unit_name")
        add_if_present(NameOID.EMAIL_ADDRESS, "email_address")
        add_if_present(NameOID.DOMAIN_COMPONENT, "domain_component")
        add_if_present(NameOID.USER_ID, "user_id")
        add_if_present(NameOID.GIVEN_NAME, "given_name")
        add_if_present(NameOID.SURNAME, "surname")
        add_if_present(NameOID.TITLE, "title_or_honorific")
        add_if_present(NameOID.PSEUDONYM, "pseudonym")
        add_if_present(NameOID.UNSTRUCTURED_NAME, "unstructured_name")


        if "custom_oids" in dn_root:
            for oid, oid_value in dn_root["custom_oids"].items():
                try:
                    oid_name = x509.ObjectIdentifier(oid)

                    if not isinstance(oid_value, str):
                        raise ValueError(f"Invalid value for OID {oid}: {oid_value}")

                    rdn_list.append(x509.NameAttribute(oid_name, oid_value))

                except ValueError as invalid_oid:
                    logger.error(
                        f"{oid}:{oid_value} is not a valid OID combination, {invalid_oid}")

        return x509.Name(rdn_list)

    def build_x509_extensions(self, template: dict, csr: object) -> object:
        """Defines the X509 v3 extensions for the CSR."""

        def build_critical_result(root: dict) -> bool:
            """Builds the critical result of a given extension"""

            critical_choice = root.get("critical", [])

            if critical_choice:
                logger.debug("Found critical choice to be True.")
                return True

            else:
                logger.debug("Critical choice is False")
                return False

        def build_san(ext_root: dict) -> object:
            """
            Builds the Subject Alternative Name Extension
            Supports DNS and IP address
            """

            subject_alt_names_values = []

            san_root = ext_root["subject_alternative_names"]

            # DNS SANs
            dns_items = san_root.get("dns", [])

            if dns_items:
                logger.info("Found DNS SANs")
                for dns_name in dns_items:
                    try:
                        subject_alt_names_values.append(x509.DNSName(dns_name))

                    except Exception as dns_san_error:
                        logger.warning(
                            f"Invalid DNS entry: {dns_name}. Error: {dns_san_error}. Skipping..."
                        )

            else:
                logger.info("No DNS SANs found.")

            # IP Address (v4) SANs
            ip_items = san_root.get("ip_address", [])

            if ip_items:
                logger.info("Found IP SANs")
                for ip_addr in ip_items:
                    try:
                        ip_value = ipaddress.ip_address(ip_addr)  # Works for IPv4 and IPv6
                        subject_alt_names_values.append(x509.IPAddress(ip_value))

                    except Exception as ip_san_error:
                        logger.warning(
                            f"Invalid IP address entry: {ip_addr}. Error: {ip_san_error}. Skipping..."
                        )

            else:
                logger.info("No IP entries found.")

            if subject_alt_names_values:
                logger.info(f"Successfully built SAN with {len(subject_alt_names_values)} entries.")
                san_object = x509.SubjectAlternativeName(subject_alt_names_values)

            else:
                logger.warning("No valid SAN entries were found. Returning None.")
                return None

            # Checking for Critical
            san_critical_choice = build_critical_result(san_root)

            return san_object, san_critical_choice

        def build_basic_constraints(ext_root: dict) -> object:
            """Builds the Basic Constraints Extension"""

            bc_root = ext_root.get("basic_constraints", [])

            if not bc_root:
                logger.warning("Basic Constraints not found")
                return None

            try:
                # CA True/False
                logger.debug("Checking for CA True/False")
                ca_choice = bc_root.get("ca", [])
                logger.info(f"Found CA:{ca_choice}")

                if ca_choice is True:
                    # Path Length
                    logger.debug("Checking for Path Length")
                    path_length_choice = bc_root.get("path_length", [])
                    logger.info(f"Found Path Length:{path_length_choice}")

                else:
                    path_length_choice = None
                    logger.info("Setting Path Length to None since CA is False")

                bc_object = x509.BasicConstraints(ca=ca_choice, path_length=path_length_choice)

                logger.info("Successfully built Basic Constraints")

                # Checking for Critical
                bc_critical_choice = build_critical_result(bc_root)

                return bc_object, bc_critical_choice

            except Exception as bc_error:
                logger.info(f"Basic Constraints Building Error: {bc_error}")
                return None

        def build_key_usage(ext_root: dict) -> object:
            """Builds the Key Usage Extension"""

            ku_root = ext_root.get("key_usage", [])

            if not ku_root:
                logger.warning("Key Usage not found")
                return None

            if ku_root.get("digital_signature") is True:
                ku_ds = True
            else:
                ku_ds = False

            if ku_root.get("key_encipherment") is True:
                ku_ke = True
            else:
                ku_ke = False

            if ku_root.get("content_commitment(non_repudiation)") is True:
                ku_cc = True
            else:
                ku_cc = False

            if ku_root.get("data_encipherment") is True:
                ku_de = True
            else:
                ku_de = False

            # This must be done because Encipher/Decipher can only be added if Key Agreement is true
            if ku_root.get("key_agreement") is True:
                ku_ka = True
                if ku_root.get("encipher_only") is True:
                    ku_eo = True
                else:
                    ku_eo = False

                if ku_root.get("decipher_only") is True:
                    ku_do = True
                else:
                    ku_do = False
            else:
                ku_ka = False
                ku_do = False
                ku_eo = False

            if ku_root.get("key_cert_sign(certificate_sign)") is True:
                ku_kcs = True
            else:
                ku_kcs = False

            if ku_root.get("crl_sign") is True:
                ku_cs = True
            else:
                ku_cs = False

            # Create KU Object
            ku_object = x509.KeyUsage(
                digital_signature=ku_ds,
                key_encipherment=ku_ke,
                content_commitment=ku_cc,
                data_encipherment=ku_de,
                key_agreement=ku_ka,
                key_cert_sign=ku_kcs,
                crl_sign=ku_cs,
                encipher_only=ku_eo,
                decipher_only=ku_do,
            )

            # Checking for Critical
            ku_critical_choice = build_critical_result(ku_root)

            return ku_object, ku_critical_choice

        def build_extended_key_usage(ext_root: dict) -> object:
            """Builds v3 extended key usage"""

            eku_root = ext_root.get("extended_key_usage", [])

            if not eku_root:
                logger.warning("Extended Key Usage not found")
                return None

            eku_list = []

            if eku_root.get("tls_server_auth") is True:
                eku_list.append(x509.oid.ExtendedKeyUsageOID.SERVER_AUTH)

            if eku_root.get("tls_client_auth") is True:
                eku_list.append(x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH)

            if eku_root.get("code_signing") is True:
                eku_list.append(x509.oid.ExtendedKeyUsageOID.CODE_SIGNING)

            if eku_root.get("email_address") is True:
                eku_list.append(x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION)

            if eku_root.get("time_stamping") is True:
                eku_list.append(x509.oid.ExtendedKeyUsageOID.TIME_STAMPING)

            if eku_root.get("ocsp_signing") is True:
                eku_list.append(x509.oid.ExtendedKeyUsageOID.OCSP_SIGNING)

            if eku_root.get("any_extended_key_usage") is True:
                eku_list.append(x509.oid.ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE)

            if eku_root.get("smartcard_login") is True:
                eku_list.append(x509.oid.ExtendedKeyUsageOID.SMARTCARD_LOGON)

            if eku_root.get("kerberos_pkinit_kdc(signing_kdc_response)") is True:
                eku_list.append(x509.oid.ExtendedKeyUsageOID.KERBEROS_PKINIT_KDC)

            if eku_root.get("ipsec_ike_ipsec_internet_key_exchange") is True:
                eku_list.append(x509.oid.ExtendedKeyUsageOID.IPSEC_IKE)

            if eku_root.get("certificate_transparency_ct_precertificate_signer") is True:
                eku_list.append(x509.oid.ExtendedKeyUsageOID.CERTIFICATE_TRANSPARENCY)

            if eku_root.get("ssh_client_secure_shell_client") is True:
                ssh_client_oid = x509.ObjectIdentifier("1.3.6.1.5.5.7.3.21")
                eku_list.append(ssh_client_oid)

            if eku_root.get("ssh_server_secure_shell_server") is True:
                ssh_server_oid = x509.ObjectIdentifier("1.3.6.1.5.5.7.3.22")
                eku_list.append(ssh_server_oid)

            if eku_root.get("custom_oids"):
                for oid in eku_root["custom_oids"]["oids"]:
                    try:
                        oid_name = x509.ObjectIdentifier(oid)

                        if not isinstance(oid, str):
                            raise ValueError(f"Invalid value for OID {oid}: {oid_value}")

                        eku_list.append(oid_name)

                    except ValueError as invalid_oid:
                        logger.error(
                            f"{oid}:{oid_value} is not a valid OID combination, {invalid_oid}")

            # Checking for Critical
            eku_critical_choice = build_critical_result(eku_root)

            eku_object = x509.ExtendedKeyUsage(eku_list)

            return eku_object, eku_critical_choice

        logger.info("Building x509 Extensions")
        ext_root = template.get("x509_extensions")

        # Subject Alternative Name
        try:
            logger.debug("Attempting to build Subject Alternative Name")
            san = build_san(ext_root)
            csr = csr.add_extension(san[0], critical=san[1])
            logger.debug("Subject Alternative Name Built")

        except Exception as san_error:
            logger.warning(f"San Error: {san_error}")

        # Basic Constraints
        try:
            logger.debug("Attempting to build Basic Constraints")
            basic_constraints = build_basic_constraints(ext_root)
            csr = csr.add_extension(basic_constraints[0], critical=basic_constraints[1])
            logger.debug("Basic Constraints Built")

        except Exception as bc_error:
            logger.warning(f"Basic Constraints Error: {bc_error}")

        # Key Usage
        try:
            logger.debug("Attempting to build Key Usage")
            key_usage = build_key_usage(ext_root)
            csr = csr.add_extension(key_usage[0], critical=key_usage[1])
            logger.debug("Key Usage Built")

        except Exception as ku_error:
            logger.warning(f"Key Usage Error: {ku_error}")

        # Extended Key Usage
        try:
            logger.debug("Attempting to build Extended Key Usage")
            extended_key_usage = build_extended_key_usage(ext_root)
            csr = csr.add_extension(extended_key_usage[0], critical=extended_key_usage[1])
            logger.debug("Extended Key Usage Built")

        except Exception as eku_error:
            logger.warning(f"Extended Key Usage Error: {eku_error}")

        logger.info("CSR Extensions built")
        return csr

    def build_signing_hash_algorithm(self, template: dict) -> object:
        """
        Builds hash object based on chosen algorithm
        Allowed hashes:
            hashes.SHA224,
            hashes.SHA256, (default)
            hashes.SHA384,
            hashes.SHA512,
            hashes.SHA3_224,
            hashes.SHA3_256,
            hashes.SHA3_384,
            hashes.SHA3_512
        """
        hash_algorithm = template.get("signing_hash_algorithm", {})

        if hash_algorithm == "SHA224":
            hash_function_obj = hashes.SHA224()

        elif hash_algorithm == "SHA256":
            hash_function_obj = hashes.SHA256()

        elif hash_algorithm == "SHA384":
            hash_function_obj = hashes.SHA384()

        elif hash_algorithm == "SHA512":
            hash_function_obj = hashes.SHA512()

        elif hash_algorithm == "SHA3_224":
            hash_function_obj = hashes.SHA3_224()

        elif hash_algorithm == "SHA3_256":
            hash_function_obj = hashes.SHA3_256()

        elif hash_algorithm == "SHA3_384":
            hash_function_obj = hashes.SHA3_384()

        elif hash_algorithm == "SHA3_512":
            hash_function_obj = hashes.SHA3_512()

        else:
            # Defaults to SHA256
            hash_function_obj = hashes.SHA256()

        logger.info(f"Using {hash_function_obj.name} for signing")

        return hash_function_obj

    def build_challenge_password(self, template: dict) -> object:
        """Builds Challenge Password. Prompts if true"""

        if template.get("challenge_password"):
            logger.info(f"Challenge Password set to True")
            return getpass("Enter the password you would like to use for the challenge: ").encode()

        else:
            logger.info("Challenge Password False")
            return False

    def build_csr(self, csr: object, private_key: object, signing_hash_algorithm: object) -> object:
        """Signs the CSR using private key and signing hash function"""

        try:
            logger.info("Signing CSR")
            built_csr = csr.sign(private_key, signing_hash_algorithm, backend=default_backend())
            logger.info("Successfully built CSR")
            return built_csr

        except Exception as csr_error:
            logger.warning(f"Could not build CSR: {csr_error}")

    def build_csr_output(self, template: dict, csr: object, random_name: str) -> object:
        """Build the CSR output. Creates a file if defined"""


        output_config_root = template.get("csr_output_config", [])

        if not output_config_root:
            logger.warning("Output config not found")
            return None

        # First, pick file name
        if output_config_root.get("random_output_file_name") is True:
            logger.debug("Creating CSR with a random name")

            if (
                template["private_key_config"]["new_private_key_config"]["random_private_key_name"]
                is True
            ):
                file_name = random_name

            else:
                file_name = "".join(choices(ascii_lowercase, k=12))

            logger.debug(f"Filename is {file_name}")

        else:
            file_name = output_config_root.get("csr_output_file_name", [])

            if file_name:
                logger.debug(f"Filename is {file_name}")

            else:
                logger.warning("File name not found")
                file_name = None

        # Ensure the directory exists
        output_path = CSR_DIR / file_name
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Next, get output format
        output_format = output_config_root.get("output_format", [])

        if output_format:
            output_format = output_format.upper()
            logger.debug("Found output_format")
            if output_format == "DER":
                logger.debug("Using DER format")
                chosen_encoding = serialization.Encoding.DER

            else:
                logger.debug("Using PEM format")
                chosen_encoding = serialization.Encoding.PEM

        # Default to PEM
        else:
            logger.warning("No output found. Defaulting to PEM")
            chosen_encoding = serialization.Encoding.PEM

        # Last, write to file

        if file_name:
            with open(output_path, "wb") as out_file:
                out_file.write(csr.public_bytes(encoding=chosen_encoding))
                logger.info(f"CSR PEM written to {output_path}")


def run_template(args):
    """
    Ultimate CSR for Templates- By: pkiscape.com
    """

    if args.template:

        if args.verbose:
            logger.setLevel(logging.DEBUG)

        # Ensure the directory exists
        template_path = TEMPLATES_DIR / args.template
        template_path.parent.mkdir(parents=True, exist_ok=True)

        check = template_checker(filename=template_path, verbosity=args.verbose)
        if check:
            try:
                with open(template_path, "r",encoding="utf-8") as csr_file:
                    json_csr_file = json.load(csr_file)

            except (FileNotFoundError, json.JSONDecodeError) as file_load_error:
                logger.error(f"Error loading template: {file_load_error}")
                sys.exit(1)

            csr_bundle = CSRBundle(template=json_csr_file)

            if args.out:
                csr_out = csr_bundle.built_csr.public_bytes(
                    encoding=serialization.Encoding.PEM
                ).decode("utf-8")
                print(f"\n{csr_out}")
