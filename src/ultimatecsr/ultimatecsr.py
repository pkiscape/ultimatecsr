#!/usr/bin/env python3

"""
=========================================
Ultimate CSR tool
=========================================

@author    pkiscape.com
@link      https://github.com/pkiscape

"""

import argparse
from cli import run_cli
from template import run_template

def main():
    parser = argparse.ArgumentParser(prog="ultimatecsr", description="Ultimate CSR Tool")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # CLI Subcommand
    cli_parser = subparsers.add_parser("cli", help="Interactive CLI-based CSR generation")
    cli_parser.add_argument("-p", "--private-key", nargs="?", help="Define your existing private key.")
    cli_parser.add_argument("-ck", "--create-key", nargs="?", const="privatekey.pem", help="Create a private key.")
    cli_parser.add_argument("-pkf", "--private-key-format", type=str.upper, choices=["PKCS1", "PKCS8", "OPENSSH"], default="PKCS8")
    cli_parser.add_argument("-ka", "--key-algorithm", type=str.upper, choices=["RSA2048", "RSA4096", "SECP256R1", "SECP384R1", "SECP521R1", "SECP256K1"], default="SECP384R1")
    cli_parser.add_argument("-e", "--encrypt", action="store_true", help="Encrypt the private key")
    cli_parser.add_argument("-o", "--out", help="CSR output filename")
    cli_parser.add_argument("-ha", "--hash-algorithm", type=str.upper, default="SHA256", choices=["SHA224", "SHA256", "SHA384", "SHA512", "SHA3_224", "SHA3_256", "SHA3_384", "SHA3_512"])
    cli_parser.add_argument("-v", "--verbose", action="store_true")
    cli_parser.add_argument("-m", "--mode", type=str.lower, choices=["short", "long"], default="long")

    # Template Subcommand
    template_parser = subparsers.add_parser("template", help="JSON template-based CSR generation")
    template_parser.add_argument("-t", "--template", nargs="?", help="Define your template file.")
    template_parser.add_argument("-o", "--out", action="store_true", help="Print the CSR PEM")
    template_parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()

    if args.command == "cli":
        run_cli(args)
    elif args.command == "template":
        run_template(args)

if __name__ == "__main__":
    main()
