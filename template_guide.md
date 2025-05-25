# Template guide

**See the templates/ directory for examples**

| Field                                                                 | Type                          | Description                                         |
|-----------------------------------------------------------------------|-------------------------------|--------------------------------------------------------|
| template_name                                                         | string                        | Name of your template                                  |
| version                                                               | string                        | Version of your template                               |
| description                                                           | string                        | Description of the template                 |
| author                                                                | string                        | Enter in your name here                                |
| private_key_config.create_new_private_key                            | true/false                    | Specify if you want to create a new private key         |
| private_key_config.private_key_overwrite_protection                  | true/false                    | Prevents your private key from being overridden |
| private_key_config.new_private_key_config.private_key_filename       | string                        | Specify the name you want to give to your private key file |
| private_key_config.new_private_key_config.random_private_key_name    | true/false                    | Set to true if you want a random filename              |
| private_key_config.new_private_key_config.key_algorithm              | string                        | RSA2048, RSA4096, SECP256R1, SECP384R1, SECP521R1,  SECP256K1 |
| private_key_config.new_private_key_config.encrypt                    | true/false                    | Encrypts Private key                                   |
| private_key_config.new_private_key_config.private_key_format         | string                        | PKCS1, PKCS8, OPENSSH                                  |
| private_key_config.existing_private_key_config.private_key_filename  | string                        | If you have an existing private key file, define the name here |
| x509_subject.serial_number                                            | string                        | Define serial number                                  |
| x509_subject.common_name                                              | string                        | Define Common Name                                   |
| x509_subject.organization_name                                        | string                        | Define Organization Name                              |
| x509_subject.state_or_province_name (full name)                       | string                        | Define State/Province Name                              |
| x509_subject.street_address                                           | string                        | Define Street Address                              |
| x509_subject.postal_code                                              | string                        | Define Postal Code                              |
| x509_subject.locality_name                                            | string                        | Define Locality Name                              |
| x509_subject.organizational_unit_name                                 | string                        | Define Organizational Unit Name                          |
| x509_subject.email_address                                            | string                        | Define Email Address                              |
| x509_subject.domain_component                                         | string                        | Define Domain Component                              |
| x509_subject.user_id                                                  | string                        | Define UserID                                  |
| x509_subject.given_name                                               | string                        | Define Given Name                              |
| x509_subject.initials                                                 | string                        | Define initials                               |
| x509_subject.surname                                                  | string                        | Define Surname                                |
| x509_subject.title_or_honorific                                       | string                        | Define Title/honorific                              |
| x509_subject.pseudonym                                                | string                        | Define Pseudonym                                   |
| x509_subject.unstructured_name                                        | string                        | Define Unstructured Name                              |
| x509_subject.custom_oids.2.5.4.24                                     | string                        | Define OID(s) and value(s)                               |
| x509_extensions.subject_alternative_names.dns                        | list of strings               | Enter in fully qualified domain names like: [example.com, test.example.com] |
| x509_extensions.subject_alternative_names.ip_address                 | list of strings               | Enter in IPv4 addresses, like [192.168.1.99, 192.168.1.100]                          |
| x509_extensions.subject_alternative_names.critical                   | true/false                    | Sets critical or not                                   |
| x509_extensions.basic_constraints.ca                                 | true/false                    | CA=true is a CA certificate, CA=false is an end-entity certificate  |
| x509_extensions.basic_constraints.path_length                        | null/integer                  | Path Length if CA=true           |
| x509_extensions.basic_constraints.critical                           | true/false                    | Sets critical or not                                   |
| x509_extensions.key_usage.digital_signature                          | true/false                    | Sets this Key usage value as =true/false               |
| x509_extensions.key_usage.key_encipherment                           | true/false                    |  Sets this Key usage value as =true/false               |
| x509_extensions.key_usage.content_commitment(non_repudiation)       | true/false                    | Sets this Key usage value as =true/false  |
| x509_extensions.key_usage.data_encipherment                          | true/false                    | Sets this Key usage value as =true/false  |
| x509_extensions.key_usage.key_agreement                              | true/false                    |  Sets this Key usage value as =true/false |
| x509_extensions.key_usage.encipher_only                              | true/false                    |  Sets this Key usage value as =true/false         |
| x509_extensions.key_usage.decipher_only                              | true/false                    |  Sets this Key usage value as =true/false    |
| x509_extensions.key_usage.key_cert_sign(certificate_sign)           | true/false                    |  Sets this Key usage value as =true/false   |
| x509_extensions.key_usage.crl_sign                                   | true/false                    |  Sets this Key usage value as =true/false    |
| x509_extensions.key_usage.critical                                   | true/false                    |  Sets critical or not                            |
| x509_extensions.extended_key_usage.tls_server_auth                   | true/false                    |  Sets this Extended Key usage value as =true/false         |
| x509_extensions.extended_key_usage.tls_client_auth                   | true/false                    |  Sets this Extended Key usage value as =true/false        |
| x509_extensions.extended_key_usage.code_signing                      | true/false                    | Sets this Extended Key usage value as =true/false     |
| x509_extensions.extended_key_usage.email_address                     | true/false                    | Sets this Extended Key usage value as =true/false     |
| x509_extensions.extended_key_usage.time_stamping                     | true/false                    | Sets this Extended Key usage value as =true/false     |
| x509_extensions.extended_key_usage.ocsp_signing                      | true/false                    | Sets this Extended Key usage value as =true/false   |
| x509_extensions.extended_key_usage.any_extended_key_usage            | true/false                    | Sets this Extended Key usage value as =true/false    |
| x509_extensions.extended_key_usage.smartcard_login                   | true/false                    | Sets this Extended Key usage value as =true/false  |
| x509_extensions.extended_key_usage.kerberos_pkinit_kdc(signing_kdc_response) | true/false            | Sets this Extended Key usage value as =true/false  |
| x509_extensions.extended_key_usage.ipsec_ike_ipsec_internet_key_exchange | true/false               | Sets this Extended Key usage value as =true/false  |
| x509_extensions.extended_key_usage.certificate_transparency_ct_precertificate_signer | true/false     | Sets this Extended Key usage value as =true/false   |
| x509_extensions.extended_key_usage.ssh_client_secure_shell_client   | true/false                    | Sets this Extended Key usage value as =true/false   |
| x509_extensions.extended_key_usage.ssh_server_secure_shell_server   | true/false                    | Sets this Extended Key usage value as =true/false      |
| x509_extensions.extended_key_usage.critical                          | true/false                    | Sets critical or not                                 |
| x509_extensions.extended_key_usage.custom_oids.oids                 | list of strings               | Define OID(s) and value(s)               |
| signing_hash_algorithm                                               | string      | Define signing hash algorithm. Can be: SHA224, SHA256, SHA384, SHA512, SHA3_224, SHA3_256, SHA3_384, SHA3_512 |
| challenge_password                                                   | true/false                    | Define a challenege password                           |
| csr_output_config.output_format                                      | string                        | Define the format for the CSR during output. Can be: PEM or DER  |
| csr_output_config.csr_output_file_name                               | string                        | Define the output filename for the CSR          |
| csr_output_config.random_output_file_name                            | true/false                    | Define if you want the output filename for the CSR to random  |
| optional_template_metadata.created_at                                | string (ISO 8601 datetime)    | Define the template creation date as a tag |
| optional_template_metadata.updated_at                                | string (ISO 8601 datetime)    | Define the template updated date as a tag           |
| optional_template_metadata.tags.key                                  | string                        | Define a key/value pair as a tag       |
