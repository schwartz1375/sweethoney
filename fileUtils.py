#!/usr/bin/env python3

__author__ = 'Matthew Schwartz (@schwartz1375)'
__version__ = '2.6'

import base64
import math
import re

import pefile
from termcolor import cprint

# Define IoCs patterns
ioc_patterns = {
    "IPv4 addresses": r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
    "IPv6 addresses": r'\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b',
    "URLs": r'(http[s]?|ftp)://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
    "Windows file paths": r'[a-zA-Z]:\\[^\n]*\\',
    "Unix-like file paths": r'/([^\s]+)/',
    "Registry keys": r'HKEY_[^\n]*',
    "HTTP user agents": r'Mozilla/5.0',
    "Email addresses": r'[\w\.-]+@[\w\.-]+\.[a-zA-Z]{1,3}',
    "Domain/Windows filename": r'(?:[a-z]+\.)+[a-z]{2,6}',
    "Usernames and passwords": r'(?:(?:administrator|admin|user|username|passw)[\s\S]){2,}',
    "Windows services": r'SC\s+[A-Za-z]+\s+',
    "Common malware commands": r'(?:netsh\s+|powershell\s+|cmd\s+/c\s+|reg\s+add\s+|reg\s+delete\s+|certutil\s+|ping\s+|net\s+|ipconfig\s+|route\s+|curl\s+|wget\s+|ftp\s+|cscript\s+)',
    "Common JavaScript malwares": r'(?:document\.write|eval|constructor|window\.setTimeout|window\.setInterval|Function|WebSocket|ActiveXObject)',
    "SQL injection patterns": r'(?:createObject|execQuery|select\s+from|drop\s+table)',
    "IP:Port patterns": r'(?:\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b:\d{1,5})',
    "shellcode patterns": r'(?:0x[a-fA-F0-9]{2}\s*)+',
    "Hashes (MD5, SHA1, SHA256)": r'(?:[\da-fA-F]{32}|[\da-fA-F]{40}|[\da-fA-F]{64})',
    "CIDR IP address pattern": r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}\b',
    "SSH Public Key pattern": r'(?:\b\w{40}\b)',
    "SSH Private Key pattern": r'(?:\b\w{64}\b)',
    "Potential Bitcoin addresses": r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
    "Base64 encoded strings": r'(?:[A-Za-z0-9+/]{4}){6,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?',
    "RSA key patterns": r'-----BEGIN (RSA PRIVATE KEY|PUBLIC KEY)-----[\s\S]+-----END (RSA PRIVATE KEY|PUBLIC KEY)-----',
    "Usernames and passwords in base64 encoding": r'[a-zA-Z0-9_-]{64,}',
    "Tor .onion address, possible DGA": r'([a-z2-7]{16}|[a-z2-7]{56})\.onion',
    # simplified and needs additional verification
    "Credit card pattern": r'\b(?:\d{4}[ -]?){3}\d{4}\b',
    "UUID/GUID patterns": r'\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b',
    "MAC address patterns": r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})',
    # JavaScript specific patterns...
    "Basic JavaScript functions": r'(?:document\.getElementById|document\.write|window\.open|eval|new\s+Function)',
    "DOM manipulation functions": r'(?:appendChild|createElement|replaceChild)',
    "Prototype manipulation": r'\.prototype\.',
    "AJAX / Fetch calls": r'XMLHttpRequest|fetch',
    "Web storage API": r'localStorage|sessionStorage',
    "Asynchronous JavaScript": r'Promise|async|await',
    "Function declarations": r'function\s*\(',
    "Encoded JavaScript using \\xNN notation": r'(?:\\b0x[a-fA-F0-9]{2}\\b){3,}',
    "Encoded JavaScript using %NN notation": r'(?:%[a-fA-F0-9]{2}){3,}',
}


def analyzePeFile(file):
    print("[+] String Hunter...")
    user_input = input("Print all the strings? (y/n): ")
    if user_input.lower() == 'y':
        # If user inputs 'y', extract and print all strings
        print("Extracting and printing all strings:")
        extract_strings_and_detect_obfuscation(file)
    elif user_input.lower() == 'n':
        # If user inputs 'n', extract only IoCs
        print("Extracting IoCs only:")
        extract_strings_and_detect_obfuscation_only(file)
    else:
        print("Invalid input. Operation cancelled by the user.")


'''
This function uses regular expressions to find sequences of characters that are 5 characters 
or longer and fall within the ASCII printable range (!-~). For Unicode strings, it looks for 
sequences of characters that alternate between a printable ASCII character and a null byte, 
which is a common characteristic of Unicode strings in PE files.

Consider strings.py & strings_decoder.py from FLOSS, and xorsearch  
'''


def extract_strings(file):
    try:
        pe = pefile.PE(file)

        sections = pe.sections
        for section in sections:
            data = section.get_data()
            ascii_strings = re.findall(b"[!-~]{5,}", data)
            unicode_strings = re.findall(b"(?:[\x20-\x7E][\x00]){5,}", data)

            # Decode the strings and print them
            for string in ascii_strings:
                print(string.decode('ascii'))

            for string in unicode_strings:
                print(string.decode('utf-16'))

    except Exception as e:
        print(f"An error occurred: {str(e)}")


def calculate_entropy(data):
    if not data:
        return 0.0

    occurences = [float(data.count(x)) for x in range(256)]
    entropy = 0

    for frequency in occurences:
        if frequency != 0:
            frequency = float(frequency) / len(data)
            entropy = entropy - frequency * math.log(frequency, 2)

    return entropy


def extract_strings_and_detect_obfuscation(file):
    try:
        pe = pefile.PE(file)

        sections = pe.sections
        for section in sections:
            data = section.get_data()
            ascii_strings = re.findall(b"[!-~]{5,}", data)
            unicode_strings = re.findall(b"(?:[\x20-\x7E][\x00]){5,}", data)

            # Check each string against IoC patterns

            for string in ascii_strings:
                decoded_string = string.decode('ascii')
                print(decoded_string)
                for pattern_name, pattern in ioc_patterns.items():
                    if re.search(pattern, decoded_string):
                        if pattern_name == "Base64 encoded strings":
                            try:
                                base64.b64decode(decoded_string, validate=True)
                            except Exception:
                                # cprint(f'failed to decode: {decoded_string}', 'red')
                                continue  # Skip this match if it doesn't decode properly
                        cprint(
                            f'Potential IoC detected: {decoded_string}, pattern: {pattern_name}', 'yellow')
                        break

            for string in unicode_strings:
                decoded_string = string.decode('utf-16')
                print(decoded_string)
                for pattern_name, pattern in ioc_patterns.items():
                    if re.search(pattern, decoded_string):
                        if pattern_name == "Base64 encoded strings":
                            try:
                                base64.b64decode(decoded_string, validate=True)
                            except Exception:
                                # cprint(f'failed to decode: {decoded_string}', 'red')
                                continue  # Skip this match if it doesn't decode properly
                        cprint(
                            f'Potential IoC detected: {decoded_string}, pattern: {pattern_name}', 'yellow')
                        break

            # Calculate entropy of each section
            entropy = calculate_entropy(data)
            section_name = section.Name.decode('utf-8').rstrip('\x00')
            # print(f"Entropy of the section {section_name}: {entropy}")

            # If the entropy is high, it might indicate obfuscated strings
            if entropy > 7.0:
                cprint(
                    f"Warning: High entropy detected in section {section_name}. This section may contain obfuscated strings.", 'red')

    except Exception as e:
        print(f"An error occurred: {str(e)}")


def extract_strings_and_detect_obfuscation_only(file):
    try:
        pe = pefile.PE(file)

        sections = pe.sections
        for section in sections:
            data = section.get_data()
            ascii_strings = re.findall(b"[!-~]{5,}", data)
            unicode_strings = re.findall(b"(?:[\x20-\x7E][\x00]){5,}", data)

            # Check each string against IoC patterns

            for string in ascii_strings:
                decoded_string = string.decode('ascii')
                for pattern_name, pattern in ioc_patterns.items():
                    if re.search(pattern, decoded_string):
                        if pattern_name == "Base64 encoded strings":
                            try:
                                base64.b64decode(decoded_string, validate=True)
                            except Exception:
                                # cprint(f'failed to decode: {decoded_string}', 'red')
                                continue  # Skip this match if it doesn't decode properly
                        cprint(
                            f'Potential IoC detected: {decoded_string}, pattern: {pattern_name}', 'yellow')
                        break

            for string in unicode_strings:
                decoded_string = string.decode('utf-16')
                for pattern_name, pattern in ioc_patterns.items():
                    if re.search(pattern, decoded_string):
                        if pattern_name == "Base64 encoded strings":
                            try:
                                base64.b64decode(decoded_string, validate=True)
                            except Exception:
                                # cprint(f'failed to decode: {decoded_string}', 'red')
                                continue  # Skip this match if it doesn't decode properly
                        cprint(
                            f'Potential IoC detected: {decoded_string}, pattern: {pattern_name}', 'yellow')
                        break

            # Calculate entropy of each section
            entropy = calculate_entropy(data)
            section_name = section.Name.decode('utf-8').rstrip('\x00')

            # If the entropy is high, it might indicate obfuscated strings
            if entropy > 7.0:
                cprint(
                    f"Warning: High entropy detected in section {section_name}. This section may contain obfuscated strings.", 'red')

    except Exception as e:
        print(f"An error occurred: {str(e)}")
