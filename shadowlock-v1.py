#!/usr/bin/env python3
# Erwin Magielda
# This shebang line specifies that the script is to be executed using the Python 3 interpreter.
# It allows the script to be run directly on systems that support this notation.

# -----------------------------------------------------------------
# Import Statements and Environment Setup
# -----------------------------------------------------------------
import os # This module provides a portable way to use operating system dependent functionality such as file path manipulation.
import sys # This module provides access to some variables used or maintained by the interpreter, and functions that interact with the interpreter.
import argparse # This module makes it easy to write user-friendly command-line interfaces by parsing command-line arguments.
import subprocess # This module allows the script to spawn new processes, connect to their input/output/error pipes, and obtain their return codes.
import json # This module is used to work with JSON data, enabling encoding and decoding of JSON formatted text.
import shutil # This module offers a number of high-level operations on files and collections of files, such as copying and removal.
import datetime # This module supplies classes for manipulating dates and times.
import hashlib # This module implements a common interface to many different secure hash and message digest algorithms.
import hmac # This module implements keyed-hashing for message authentication, providing a way to ensure data integrity and authenticity.
import base64 # This module provides functions for encoding binary data to printable ASCII characters and decoding such encodings back to binary data.
import time # This module provides various time-related functions, including sleeping and performance timing.
import platform # This module is used to access underlying platform’s identifying data, which is useful for detecting the operating system.
import tempfile # This module is used to create temporary files and directories. It provides utilities to safely handle short-lived file storage during operations such as unpacking or backup extraction.

from getpass import getpass
# This function is used to securely prompt the user for a password without echoing, thereby protecting sensitive input.

from typing import Optional
# This import is used for type hinting purposes, and the 'Optional' type specifies that a variable may be of a certain type or None.

import xattr # This module provides a way to access and modify extended attributes on Unix-like file systems.

# The following imports are from the cryptography library and are used for cryptographic operations.
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
# This class provides an implementation of the AES algorithm in Galois/Counter Mode (GCM) which is an authenticated encryption mode.

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
# This class implements the HMAC-based Extract-and-Expand Key Derivation Function (HKDF) to derive keys from a master key.

from cryptography.hazmat.primitives import hashes
# This module provides implementations of common cryptographic hash functions.

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
# This class implements the PBKDF2 key derivation function with HMAC as its pseudorandom function.
# It is used to derive a secure cryptographic key from a passphrase.

from cryptography.hazmat.backends import default_backend
# This function provides a default cryptographic backend for cryptographic operations.

from cryptography.exceptions import InvalidTag
# This exception is raised when a decryption operation fails due to an invalid authentication tag, which helps to detect tampering.

# -----------------------------------------------------------------
# Global Paths and Constants
# -----------------------------------------------------------------
# 'metadata_directory' defines the directory in the user’s home folder where metadata files are stored.
metadata_directory = os.path.expanduser("~/.shadowmeta")

# 'config_file' is the full path to the configuration file within the metadata directory.
config_file = os.path.join(metadata_directory, "config.json")

# 'hash_backup_file' is the path to the JSON file that securely backs up file hashes.
hash_backup_file = os.path.join(metadata_directory, "hash_backup.json")

# 'log_file' represents the path to the encrypted log ledger file.
log_file = os.path.join(metadata_directory, "log.enc")

# 'salt_file' is the path to the file where the dynamic salt for configuration encryption is stored.
salt_file = os.path.join(metadata_directory, "config_salt.bin")

# 'CONFIG_VERSION' specifies the version of the configuration schema.
CONFIG_VERSION = "1.0.0"

# 'CACHE_TIMEOUT' defines the duration (in seconds) for which the cached passphrase-derived key is valid.
CACHE_TIMEOUT = 600  # Here, 600 seconds is equivalent to 10 minutes.

# -----------------------------------------------------------------
# Global Cache for Passphrase Key
# -----------------------------------------------------------------
# 'cached_key' stores the passphrase-derived key once it has been computed.
cached_key: Optional[bytes] = None

# 'cached_timestamp' records the time when the key was cached.
cached_timestamp: Optional[float] = None

# -----------------------------------------------------------------
# Cached Passphrase Key Retrieval
# -----------------------------------------------------------------
def get_cached_key() -> Optional[bytes]:
    """
    Returns the cached passphrase-derived key if it is still valid (within 10 minutes).

    This function checks whether a key has been previously cached and determines its validity
    by comparing the elapsed time since it was cached with the CACHE_TIMEOUT constant.
    If the cached key is still valid, it is returned; otherwise, None is returned.
    """
    global cached_key, cached_timestamp

    # Check if both the cached key and its corresponding timestamp are available.
    if cached_key and cached_timestamp:
        # Calculate the elapsed time since the key was cached.
        elapsed_time = time.time() - cached_timestamp
        print(f"Cached key found. Elapsed time is {elapsed_time:.2f} seconds.")

        # If the elapsed time is less than the CACHE_TIMEOUT, the cached key is still valid.
        if elapsed_time < CACHE_TIMEOUT:
            print("Cached key remains valid. Returning the cached key.")
            return cached_key
        else:
            print("Cached key has expired.")
    else:
        # If either the key or the timestamp is missing, indicate that no cached key is present.
        print("No cached key is present.")

    return None

# -----------------------------------------------------------------
# Cache Key Storage and Timestamp Recording
# -----------------------------------------------------------------
def cache_key(key: bytes) -> None:
    """
    Caches the derived key and records the current time to track its expiry.

    This function updates the global variables 'cached_key' and 'cached_timestamp'
    so that subsequent calls to get_cached_key() can verify if the key is still valid.
    """
    global cached_key, cached_timestamp # Update the global 'cached_key' with the newly derived key.
    cached_key = key # Record the current time to track when the key was cached.
    cached_timestamp = time.time() # Inform the user that a new key has been cached along with the recorded timestamp.
    print(f"New key has been cached at timestamp: {cached_timestamp}")

# -----------------------------------------------------------------
# Filesystem Check
# -----------------------------------------------------------------
def check_filesystem(directory: str) -> bool:
    """
    Checks if the given directory is on a supported filesystem (ext4, xfs, btrfs).

    This function runs the 'df -T' command to obtain the filesystem type for the specified
    directory and then verifies whether the filesystem type is one of the supported types.
    """
    # List of supported filesystem types.
    supported_filesystems = ['ext4', 'xfs', 'btrfs']
    try:
        # Execute the 'df -T' command and capture its output.
        result = subprocess.run(["df", "-T", directory],
                                capture_output=True, text=True, check=True)
        output = result.stdout.strip()
        print(f"The output of the 'df -T' command is as follows:\n{output}")

        # Split the output into separate lines.
        lines = output.split("\n")
        if len(lines) < 2:
            print("Unable to parse the output of 'df -T' for filesystem type.")
            return False

        # The second line is expected to contain the filesystem details.
        data_line = lines[1].split()
        print(f"Filesystem details parsed from the output: {data_line}")
        if len(data_line) < 2:
            print("Insufficient data found in the output to determine the filesystem type.")
            return False

        # Extract the filesystem type from the parsed details and convert it to lowercase.
        fs_type = data_line[1].lower()
        print(f"Detected filesystem type is {fs_type}")

        # Check if the detected filesystem type is within the list of supported filesystems.
        if fs_type in supported_filesystems:
            print(f"Filesystem check passed. The directory '{directory}' is on a supported filesystem ({fs_type}).")
            return True
        else:
            print(f"Filesystem check failed. The directory '{directory}' is on an unsupported filesystem ({fs_type}).")
            return False
    except Exception as e:
        print(f"An error occurred while checking the filesystem for '{directory}'. Error details: {e}")
        return False

# -----------------------------------------------------------------
# Secure File Deletion
# -----------------------------------------------------------------
def secure_delete(file_path: str) -> None:
    """
    Securely deletes a file using the 'shred' command.
    If the 'shred' command is not available or fails, then the function falls back to normal file deletion.
    """
    # Inform that secure deletion for the specified file is being initiated.
    print(f"Initiating secure deletion of {file_path}.")
    try:
        # Attempt to securely delete the file using the 'shred' command.
        subprocess.run(["shred", "--remove", file_path], check=True)
        print(f"File {file_path} has been securely deleted using shred.")
    except Exception as e:
        # If the 'shred' command fails, inform the user of the error.
        print(f"The shred command encountered an error for {file_path}: {e}")
        try:
            # Fall back to standard file deletion if secure deletion fails.
            os.remove(file_path)
            print(f"File {file_path} has been deleted using standard deletion, as shred was not available.")
        except Exception as e:
            # Inform the user if normal file deletion also fails.
            print(f"An error occurred while deleting {file_path}: {e}")

# -----------------------------------------------------------------
# Destroy File
# -----------------------------------------------------------------
def destroy_file(file_path: str) -> None:
    """
    Destroys the specified file securely.

    Steps:
      1. Logs that the destroy command has been engaged.
      2. If a configuration file exists, it loads the configuration and checks if the file
         to be destroyed is within the shadow (encrypted) folder. If it is, the process is aborted.
      3. Checks whether the file exists. If not, it prints an error and returns.
      4. On Linux systems, attempts to remove the immutable flag from the file.
      5. Securely deletes the file using the secure_delete() function.
      6. Logs the destruction event.
    """
    # Step 1: Inform that the DESTROY command has been engaged.
    print("DESTROY command engaged...")

    # Step 2: If the configuration file exists, load it and verify the file location.
    if os.path.exists(config_file):
        # Load the configuration from the configuration file.
        config = load_configuration()
        # Obtain the absolute path of the shadow (encrypted) folder from the configuration.
        shadow_folder = os.path.abspath(config.get("encrypted_directory", ""))
        # Obtain the absolute path of the file to be destroyed.
        target_path = os.path.abspath(file_path)
        print(f"Shadow folder is located at: {shadow_folder}")
        print(f"Target file path is: {target_path}")
        # If the target file is within the shadow folder, abort the destruction process.
        if target_path.startswith(shadow_folder):
            print("Error. It is not permitted to destroy files within the shadow folder.")
            return

    # Step 3: Check whether the file exists. If it does not exist, inform the user and exit.
    if not os.path.exists(file_path):
        print(f"The file {file_path} was not found.")
        return

    # Step 4: If the operating system is Linux, attempt to remove the immutable flag from the file.
    if is_linux_system():
        try:
            subprocess.run(["chattr", "-i", file_path], check=True)
            print(f"The immutable flag has been removed from {file_path}.")
        except Exception as e:
            print(f"An error occurred while removing the immutable flag from {file_path}: {e}")

    # Step 5: Securely delete the file using the secure_delete() function.
    secure_delete(file_path)

    # Step 6: Log the destruction event.
    # Reload the configuration to obtain the encryption key.
    config = load_configuration()
    # Convert the file encryption key from hexadecimal to bytes.
    master_key = bytes.fromhex(config["file_enc_key"])
    append_log_entry(log_file, master_key, "Command", f"Destroyed file {file_path}")

# -----------------------------------------------------------------
# Passphrase Prompting and Strength Check
# -----------------------------------------------------------------
def is_strong_passphrase(passphrase: str) -> bool:
    """
    Checks if the provided passphrase is strong.

    A strong passphrase must:
      - Be at least 8 characters long.
      - Contain at least one alphabetical character.
      - Contain at least one digit.

    Returns True if all criteria are met, otherwise False.
    """
    # Verify that the passphrase meets the minimum length requirement.
    length_ok = len(passphrase) >= 8

    # Verify that the passphrase contains at least one alphabetical character.
    has_letter = any(c.isalpha() for c in passphrase)

    # Verify that the passphrase contains at least one digit.
    has_digit = any(c.isdigit() for c in passphrase)

    # Combine all conditions to determine if the passphrase is strong.
    strong = length_ok and has_letter and has_digit

    # Print the results of the passphrase strength evaluation.
    print(f"Passphrase strength check: length_ok={length_ok}, has_letter={has_letter}, has_digit={has_digit}, strong={strong}")

    return strong

def prompt_for_new_passphrase() -> bytes:
    """
    Prompts the user for a new passphrase twice (for confirmation) and caches the derived key.

    The function ensures that the passphrase:
      - Is entered twice and both entries match.
      - Meets the strength requirements (it must be at least 8 characters long, include alphabetical characters and digits).
    Once a valid passphrase is provided, the function uses PBKDF2HMAC with a dynamic salt to derive a 32-byte encryption key,
    caches the key for future use, and returns the derived key.
    """
    while True:
        # Prompt the user to enter the new passphrase.
        pass1 = getpass("Enter a strong config encryption passphrase (min 8 chars, letters & digits): ")
        # Prompt the user to confirm the passphrase.
        pass2 = getpass("Confirm the passphrase: ")

        # Check if both passphrase entries match.
        if pass1 != pass2:
            print("Passphrases do not match. Please try again.")
            continue
        else:
            print("Passphrase entries match.")

        # Verify that the passphrase meets the strength requirements.
        if not is_strong_passphrase(pass1):
            print("Weak passphrase. It must be at least 8 characters and include letters and digits.")
            continue
        else:
            print("Passphrase meets strength requirements.")

        # Retrieve the dynamic salt from the salt file.
        salt = get_config_salt()
        print(f"Retrieved salt: {salt.hex()}")

        # Derive a 32-byte key using PBKDF2HMAC with SHA256, the dynamic salt and 100000 iterations.
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(pass1.encode())
        print(f"Derived key: {key.hex()}")

        # Cache the derived key for future use.
        cache_key(key)
        print("Key has been cached successfully.")

        return key

def prompt_for_existing_passphrase(encrypted_data: bytes) -> bytes:
    """
    Prompts the user for the existing passphrase to decrypt the configuration.
    The user is allowed up to three attempts. If a cached key is available and valid, it is used.
    """
    attempts = 0  # Initialise the number of attempts
    while attempts < 3:
        # Check if a previously derived key is cached and valid
        cached = get_cached_key()
        if cached:
            try:
                # Attempt to decrypt the configuration with the cached key
                _ = decrypt_bytes(encrypted_data, cached)
                return cached  # Return the cached key if decryption is successful
            except Exception:
                # If decryption fails with the cached key, proceed to prompt the user
                pass

        # Prompt the user to enter the configuration encryption passphrase
        p = getpass("Enter config encryption passphrase to decrypt config: ")
        # Verify the strength of the entered passphrase
        if not is_strong_passphrase(p):
            print("Passphrase does not meet requirements.")
            attempts += 1
            continue

        # Retrieve the dynamic salt from the salt file
        salt = get_config_salt()
        # Set up the PBKDF2HMAC key derivation function with SHA256, the dynamic salt and 100000 iterations
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        try:
            # Derive the encryption key from the provided passphrase
            key = kdf.derive(p.encode())
            # Attempt to decrypt the configuration using the newly derived key
            _ = decrypt_bytes(encrypted_data, key)
            # Cache the derived key for future use
            cache_key(key)
            return key
        except Exception:
            attempts += 1
            print(f"Failed to decrypt config. Attempt {attempts} of 3.")
            if attempts >= 3:
                print("Too many failed attempts. Cooling down for 30 seconds.")
                time.sleep(30)
                sys.exit(1)
    sys.exit(1)

# -----------------------------------------------------------------
# Dynamic Salt Handling
# -----------------------------------------------------------------
def get_config_salt() -> bytes:
    """
    Retrieves (or generates and stores) the dynamic salt from the salt file.

    The salt is used to derive encryption keys for the configuration. If the salt file does not exist,
    a new salt is generated, saved to the file and then returned. Otherwise, the existing salt is read and returned.
    """
    if not os.path.exists(salt_file):
        # Generate a new random salt consisting of 16 bytes.
        salt = os.urandom(16)
        # Open the salt file in write-binary mode and store the newly generated salt.
        with open(salt_file, "wb") as f:
            f.write(salt)
    else:
        # Open the existing salt file in read-binary mode and retrieve the salt.
        with open(salt_file, "rb") as f:
            salt = f.read()
    return salt

# -----------------------------------------------------------------
# Cryptographic Operations
# -----------------------------------------------------------------
def generate_encryption_key() -> bytes:
    """
    Generates a random 256-bit AES key for file encryption.
    This key is generated using AESGCM and will be used in later encryption and decryption operations.
    """
    # Generate and return a 256-bit (32-byte) AES key.
    return AESGCM.generate_key(bit_length=256)

def encrypt_bytes(data: bytes, key: bytes) -> bytes:
    """
    Encrypts the provided data using AES-GCM; returns the nonce concatenated with the ciphertext.

    AES-GCM provides both confidentiality and integrity verification.
    A random nonce of 12 bytes is generated and used in the encryption process.
    The nonce is then prepended to the ciphertext so it can be recovered for decryption.
    """
    # Initialise the AESGCM object with the provided key.
    aesgcm = AESGCM(key)
    # Generate a random nonce of 12 bytes.
    nonce = os.urandom(12)
    # Encrypt the data using AES-GCM. No additional authenticated data is used.
    ciphertext = aesgcm.encrypt(nonce, data, None)
    # Return the nonce concatenated with the ciphertext.
    return nonce + ciphertext

def decrypt_bytes(enc_data: bytes, key: bytes) -> bytes:
    """
    Decrypts data that has been encrypted with AES-GCM.

    The encrypted data is expected to have the nonce (12 bytes) at the beginning, followed by the ciphertext.
    The function retrieves the nonce and ciphertext, then decrypts and returns the original plaintext.
    """
    # Initialise the AESGCM object with the provided key.
    aesgcm = AESGCM(key)
    # Extract the first 12 bytes, which represent the nonce.
    nonce = enc_data[:12]
    # Extract the remaining bytes, which represent the ciphertext.
    ciphertext = enc_data[12:]
    # Decrypt the data using the nonce and return the plaintext.
    return aesgcm.decrypt(nonce, ciphertext, None)

def encrypt_file(src: str, dst: str, key: bytes) -> None:
    """
    Encrypts the file located at 'src' and writes the encrypted data to 'dst'.

    The function reads the file contents in binary mode, encrypts the data using AES-GCM,
    and then writes the encrypted result (nonce + ciphertext) to the destination file.
    """
    # Open the source file in binary read mode.
    with open(src, "rb") as f:
        data = f.read()
    # Encrypt the read data using the provided key.
    enc_data = encrypt_bytes(data, key)
    # Write the encrypted data to the destination file in binary write mode.
    with open(dst, "wb") as f:
        f.write(enc_data)


def decrypt_file_contents(path: str, key: bytes) -> bytes:
    """
    Decrypts and returns the file contents from the given file path.

    The file is read in binary mode, and its content is decrypted using AES-GCM.
    The resulting plaintext is returned.
    """
    # Open the file in binary read mode.
    with open(path, "rb") as f:
        data = f.read()
    # Decrypt the file contents and return the plaintext.
    return decrypt_bytes(data, key)

def compute_sha256(data: bytes) -> bytes:
    """
    Computes and returns the SHA-256 hash of the provided data.

    This function utilises the hashlib library to calculate the secure hash of the given binary data.
    The SHA-256 hash is returned as a byte sequence.
    """
    # Initialise a new SHA-256 hash object.
    hasher = hashlib.sha256()
    # Update the hash object with the data.
    hasher.update(data)
    # Return the computed hash digest.
    return hasher.digest()

# -----------------------------------------------------------------
# Per-File Key Derivation
# -----------------------------------------------------------------
def derive_file_encryption_key(master_key: bytes, filename: str) -> bytes:
    """
    Derives a per-file key from the master key using HKDF with the filename as salt.

    This function employs the HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
    to generate a unique encryption key for each file based on the master key. The filename is used
    as the salt to ensure that each file receives a distinct key.
    """
    # Initialise HKDF with the following parameters:
    # - algorithm: SHA256 is used for hashing.
    # - length: Derive a 32-byte key.
    # - salt: The filename is encoded to bytes and used as the salt.
    # - info: Provide additional context with the byte string 'file encryption'.
    # - backend: Use the default cryptographic backend.
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=filename.encode(),
        info=b'file encryption',
        backend=default_backend()
    )
    # Derive and return the per-file encryption key from the master key.
    return hkdf.derive(master_key)

# -----------------------------------------------------------------
# Extended Attributes and Encrypted Hash Backup
# -----------------------------------------------------------------
def backup_file_hash(filename: str, enc_hash: bytes) -> None:
    """
    Backs up the encrypted hash to an encrypted JSON file.

    This function reads any existing backup from the designated file, decrypts it using the master key,
    and loads it as a dictionary. It then updates the dictionary with the encrypted hash for the specified file,
    re-encrypts the updated dictionary and writes it back to the backup file.
    """
    backup = {}  # Initialise an empty dictionary for backups.

    # Check if the backup file exists.
    if os.path.exists(hash_backup_file):
        try:
            # Load the current configuration to obtain the master file encryption key.
            config = load_configuration()
            master_key = bytes.fromhex(config["file_enc_key"])
            # Read the encrypted backup file.
            with open(hash_backup_file, "rb") as f:
                encrypted_backup = f.read()
            # Decrypt the backup contents and decode it from UTF-8.
            decrypted_backup = decrypt_bytes(encrypted_backup, master_key).decode('utf-8')
            # Convert the JSON string to a dictionary.
            backup = json.loads(decrypted_backup)
        except Exception:
            # If any error occurs, initialise backup as an empty dictionary.
            backup = {}

    # Add or update the entry for the specified filename.
    backup[filename] = base64.b64encode(enc_hash).decode()
    # Convert the updated backup dictionary back to a formatted JSON string.
    backup_json = json.dumps(backup, indent=4)

    # Reload the configuration to obtain the master key.
    config = load_configuration()
    master_key = bytes.fromhex(config["file_enc_key"])
    # Encrypt the backup JSON string.
    encrypted_backup = encrypt_bytes(backup_json.encode(), master_key)
    # Write the encrypted backup back to the backup file.
    with open(hash_backup_file, "wb") as f:
        f.write(encrypted_backup)

    print(f"Backup updated for {filename} in encrypted hash_backup.json")

# -----------------------------------------------------------------
# Extended Attributes for File Hash Storage
# -----------------------------------------------------------------
def store_file_hash(enc_filepath: str, file_data: bytes, key: bytes) -> None:
    """
    Computes the SHA-256 hash of file_data, encrypts it, stores it as an extended attribute,
    and backs it up.
    """
    # Compute the SHA-256 hash of the file data and convert it to a hexadecimal string.
    file_hash = compute_sha256(file_data).hex()
    # Encrypt the hash using the provided key.
    enc_hash = encrypt_bytes(file_hash.encode(), key)
    try:
        # Store the encrypted hash in the extended attributes of the encrypted file under 'user.shadowhash'.
        xattr.setxattr(enc_filepath, "user.shadowhash", enc_hash)
        print(f"Stored encrypted hash in xattr for {os.path.basename(enc_filepath)} (SHA-256: {file_hash})")
        # Update the backup with the encrypted hash for the file.
        backup_file_hash(os.path.basename(enc_filepath), enc_hash)
    except Exception as e:
        print(f"Error setting xattr on {enc_filepath}: {e}")

# -----------------------------------------------------------------
# File Hash Verification
# -----------------------------------------------------------------
def verify_file_hash(enc_filepath: str, file_data: bytes, key: bytes) -> bool:
    """
    Verifies that the SHA-256 hash computed from file_data matches the decrypted stored hash.

    This function computes the SHA-256 hash of the provided file data, then compares it against
    the decrypted hash stored in the extended attributes of the encrypted file.
    """
    # Compute the SHA-256 hash of the provided file data and convert it to a hexadecimal string.
    computed = compute_sha256(file_data).hex()
    try:
        # Retrieve the encrypted hash from the extended attributes (stored under "user.shadowhash").
        stored = xattr.getxattr(enc_filepath, "user.shadowhash")
        # Decrypt the stored hash using the provided key and decode it into a string.
        decrypted = decrypt_bytes(stored, key).decode()
        # Compare and return whether the computed hash matches the decrypted hash.
        return computed == decrypted
    except Exception as e:
        print(f"Error retrieving/decrypting xattr from {enc_filepath}: {e}")
        return False

# -----------------------------------------------------------------
# File and Directory Utilities
# -----------------------------------------------------------------
def hide_directory(directory: str) -> str:
    """
    Renames a directory to a hidden directory (by prefixing the name with a dot) if it is not already hidden,
    and returns its absolute path.
    """
    abs_path = os.path.abspath(directory)  # Convert the directory path to an absolute path.
    base = os.path.basename(abs_path)        # Extract the base name of the directory.
    if not base.startswith("."):
        # If the directory is not hidden, create a new path with the base name prefixed with a dot.
        new_path = os.path.join(os.path.dirname(abs_path), "." + base)
        os.rename(abs_path, new_path)  # Rename the directory to the new hidden path.
        print(f"Renamed directory to hidden: {new_path}")
        return new_path
    return abs_path

def set_file_read_only(path: str) -> None:
    """
    Sets the file permissions to read-only (mode 444).
    """
    os.chmod(path, 0o444)  # Change file permissions to read-only.
    print(f"Set file to read-only: {os.path.basename(path)}")

def set_directory_read_only(directory: str) -> None:
    """
    Sets the directory permissions to read-only (mode 555).
    """
    os.chmod(directory, 0o555)  # Change directory permissions to read-only.
    print(f"Set directory to read-only: {os.path.basename(directory)}")

def make_file_writable(path: str) -> None:
    """
    Makes a file writable (mode 644).
    """
    os.chmod(path, 0o644)  # Change file permissions to make it writable.
    print(f"Made file writable: {os.path.basename(path)}")

def is_linux_system() -> bool:
    """
    Returns True if the operating system is Linux, otherwise False.
    """
    return platform.system() == "Linux"  # Check if the operating system is Linux.

def set_directory_immutable(directory: str) -> None:
    """
    Sets the immutable flag on a directory (Linux only).

    This flag prevents modifications to the files within the directory.
    """
    if not is_linux_system():
        print("Immutable flag not supported on this platform.")
        return
    try:
        # Set the immutable flag recursively using the 'chattr' command.
        subprocess.run(["chattr", "-R", "+i", directory], check=True)
        print(f"Immutable flag set on: {directory}")
    except subprocess.CalledProcessError as e:
        print(f"Error setting immutable flag on {directory}: {e}")

def remove_directory_immutable(directory: str) -> None:
    """
    Removes the immutable flag from a directory (Linux only).
    """
    if not is_linux_system():
        print("Immutable flag not supported on this platform; skipping.")
        return
    try:
        # Remove the immutable flag recursively using the 'chattr' command.
        subprocess.run(["chattr", "-R", "-i", directory], check=True)
        print(f"Immutable flag removed from: {directory}")
    except subprocess.CalledProcessError as e:
        print(f"Error removing immutable flag from {directory}: {e}")

def get_file_stats(path: str) -> (int, str):
    """
    Returns a tuple containing the file size in bytes and the last modified date and time as a string.

    The last modified time is formatted as 'YYYY-MM-DD HH:MM:SS'.
    """
    stat_info = os.stat(path)  # Retrieve the file's statistics.
    size = stat_info.st_size   # Get the file size in bytes.
    mtime = datetime.datetime.fromtimestamp(stat_info.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
    return size, mtime

# -----------------------------------------------------------------
# Centralized Logging Functions
# -----------------------------------------------------------------
def read_log(log_path: str, master_key: bytes) -> str:
    """
    Decrypts and returns the current log content.

    If the log file does not exist, an empty string is returned.
    """
    if not os.path.exists(log_path):
        return ""
    try:
        # Open the log file in binary read mode and read its contents.
        with open(log_path, "rb") as f:
            encrypted_log = f.read()
        # Decrypt the log content using the provided master key.
        decrypted = decrypt_bytes(encrypted_log, master_key)
        # Return the decrypted log content decoded to a UTF-8 string.
        return decrypted.decode('utf-8')
    except Exception:
        # Return an empty string if any exception occurs during decryption.
        return ""

def write_log(log_path: str, master_key: bytes, log_content: str) -> None:
    """
    Encrypts the provided log content and writes it to the log file.

    The log content is encoded to UTF-8 before encryption.
    """
    # Encrypt the log content using AES-GCM.
    encrypted_log = encrypt_bytes(log_content.encode('utf-8'), master_key)
    # Write the encrypted log content to the file in binary write mode.
    with open(log_path, "wb") as f:
        f.write(encrypted_log)

def append_log_entry(log_path: str, master_key: bytes, entry_type: str, message: str,
                     file_event: str = None, file_name: str = None,
                     size: str = None, file_format: str = None, file_hash: str = None) -> None:
    """
    Appends a new log entry to the ledger.

    For command events (entry_type="Command"), only the message is used.
    For file events (entry_type="File"), additional details such as the event type,
    file name, file size, file format, and the file's SHA-256 hash are provided.
    Each entry is assigned an incremental entry number and is separated by a line containing "-----".
    """
    # Read the current log content.
    log_content = read_log(log_path, master_key)
    # Extract existing entries by looking for lines that start with "Entry".
    entries = [line for line in log_content.splitlines() if line.lstrip().startswith("Entry")]
    entry_number = len(entries) + 1  # Assign the next entry number.
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Create a HMAC signature for the log entry using the master key, timestamp, and message.
    signature = hmac.new(master_key, f"{timestamp} {message}".encode('utf-8'), hashlib.sha256).hexdigest()

    # Begin constructing the new log entry with the entry number and type.
    new_entry = f"Entry {entry_number}: {entry_type}\nTimestamp: {timestamp}\n"
    if entry_type == "Command":
        new_entry += f"Message: {message}\n"
    elif entry_type == "File":
        new_entry += f"Event: {file_event}\n"
        new_entry += f"File Name: {file_name}\n"
        new_entry += f"Size: {size}\n"
        new_entry += f"Format: {file_format}\n"
        new_entry += f"Hash (SHA-256): {file_hash}\n"
    # Add the HMAC signature and a separator line.
    new_entry += f"HMAC: {signature}\n-----\n"
    # Append the new entry to the existing log content.
    updated_log = log_content + new_entry
    # Write the updated log content back to the log file.
    write_log(log_path, master_key, updated_log)

def display_log_ledger(log_path: str, master_key: bytes) -> None:
    """
    Decrypts and displays the log ledger.

    If the log ledger is not found or cannot be decrypted, an appropriate message is displayed.
    """
    log_content = read_log(log_path, master_key)
    if not log_content:
        print("No log ledger found.")
        return
    # Display the decrypted log ledger with header and footer separators.
    print("===== LOG LEDGER =====")
    print(log_content)
    print("======================")

# -----------------------------------------------------------------
# Display Status
# -----------------------------------------------------------------
def print_status() -> None:
    """
    Displays a detailed summary of the system status including file counts,
    deployment time, and version.
    """
    # Load the current configuration from the configuration file.
    config = load_configuration()
    # Retrieve the source and encrypted directories from the configuration.
    src_dir = config["source_directory"]
    enc_dir = config["encrypted_directory"]
    # Count the number of regular source files in the source directory.
    num_source = len([f for f in os.listdir(src_dir) if os.path.isfile(os.path.join(src_dir, f))])
    # Count the number of encrypted files in the encrypted directory (files ending with '.enc').
    num_enc = len([f for f in os.listdir(enc_dir) if f.endswith(".enc")])
    # Construct a formatted string showing system status details.
    status = (
        "\n===== SYSTEM STATUS =====\n"
        f"Source Directory      : {src_dir}\n"
        f"Encrypted Directory   : {enc_dir}\n"
        f"Source Files Count    : {num_source}\n"
        f"Encrypted Files Count : {num_enc}\n"
        f"Deployment Time       : {config.get('deployment_time', 'N/A')}\n"
        f"Version               : {config.get('version', 'N/A')}\n"
        "=========================="
    )
    # Display the system status.
    print(status)
    # Reload the configuration to ensure any recent updates are captured.
    config = load_configuration()
    # Convert the stored file encryption key from hexadecimal format to bytes.
    master_key = bytes.fromhex(config["file_enc_key"])
    # Append a log entry to indicate that the status command was invoked.
    append_log_entry(log_file, master_key, "Command", "Status command invoked")

# -----------------------------------------------------------------
# Generate Report
# -----------------------------------------------------------------
def generate_forensic_report() -> None:
    """
    Generates a comprehensive forensic report including deployment details,
    system status, file metadata, and the log ledger.
    """
    # Load the current configuration.
    config = load_configuration()
    # Retrieve the source and encrypted directories.
    src_dir = config["source_directory"]
    enc_dir = config["encrypted_directory"]
    # Count the number of files in the source directory.
    num_source = len([f for f in os.listdir(src_dir) if os.path.isfile(os.path.join(src_dir, f))])
    # Count the number of encrypted files in the encrypted directory.
    num_enc = len([f for f in os.listdir(enc_dir) if f.endswith(".enc")])

    # Build the forensic report as a list of strings.
    report_lines = [
        "\n===== FORENSIC REPORT =====",
        f"Deployment Time: {config.get('deployment_time', 'N/A')}",
        f"Version        : {config.get('version', 'N/A')}",
        "",
        "----- SYSTEM STATUS -----",
        f"Source Directory      : {src_dir}",
        f"Encrypted Directory   : {enc_dir}",
        f"Source Files Count    : {num_source}",
        f"Encrypted Files Count : {num_enc}",
        "",
        "----- FILE METADATA -----"
    ]

    # For each file in the source directory, append its metadata (filename, size, and last modified time).
    for fname in os.listdir(src_dir):
        sfile = os.path.join(src_dir, fname)
        if os.path.isfile(sfile):
            size, mtime = get_file_stats(sfile)
            report_lines.append(f"{fname} | {size} bytes | {mtime}")

    report_lines.append("")
    report_lines.append("----- LOG LEDGER -----")
    # Check if the log file exists.
    if os.path.exists(log_file):
        try:
            # Obtain the master key from the configuration.
            master_key = bytes.fromhex(config["file_enc_key"])
            # Read and decrypt the log ledger content.
            log_content = read_log(log_file, master_key)
            report_lines.append(log_content)
        except Exception:
            report_lines.append("Error decrypting log ledger.")
    else:
        report_lines.append("No log ledger found.")
    report_lines.append("=============================")

    # Combine all report lines into a single text block.
    report_text = "\n".join(report_lines)
    # Print the forensic report.
    print(report_text)
    # Append a log entry to indicate that the forensic report was generated.
    master_key = bytes.fromhex(config["file_enc_key"])
    append_log_entry(log_file, master_key, "Command", "Forensic report generated")

# -----------------------------------------------------------------
# Backup the System
# -----------------------------------------------------------------
def backup_system(dump_path: str) -> None:
    """
    Creates a zip archive backup of the metadata and encrypted directories.

    This function gathers the metadata and encrypted directories, copies them to a temporary
    backup location, creates a zip archive of the backup, and then removes the temporary backup.
    Finally, it logs the backup event.
    """
    print("BACKUP command engaged...")
    # Load the current configuration.
    config = load_configuration()
    enc_dir = config["encrypted_directory"]

    # Verify that both the metadata directory and the encrypted directory exist.
    if not os.path.exists(metadata_directory) or not os.path.exists(enc_dir):
        print("Missing metadata or encrypted directory. Cannot create backup.")
        return

    # Generate a timestamp string for naming the backup.
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    # Define a temporary directory for the backup within /tmp.
    backup_temp = os.path.join("/tmp", f"shadow_backup_{timestamp}")
    os.makedirs(backup_temp, exist_ok=True)

    # Define destination paths for the metadata and encrypted directories within the temporary backup.
    meta_dest = os.path.join(backup_temp, os.path.basename(metadata_directory))
    enc_dest = os.path.join(backup_temp, os.path.basename(enc_dir))
    # Copy the metadata directory to the temporary backup location.
    shutil.copytree(metadata_directory, meta_dest)
    # Copy the encrypted directory to the temporary backup location.
    shutil.copytree(enc_dir, enc_dest)

    # Define the zip archive name using the generated timestamp.
    zip_name = f"shadow_backup_{timestamp}.zip"
    zip_path = os.path.join(dump_path, zip_name)
    # Create the zip archive from the temporary backup directory.
    shutil.make_archive(zip_path.replace(".zip", ""), 'zip', root_dir=backup_temp)
    # Remove the temporary backup directory.
    shutil.rmtree(backup_temp)

    print(f"Backup created at {zip_path}")
    # Reload the configuration to get the latest keys.
    master_key = bytes.fromhex(config["file_enc_key"])
    # Log the backup creation event.
    append_log_entry(log_file, master_key, "Command", f"Backup created at {zip_path}")

# -----------------------------------------------------------------
# Restore the System
# -----------------------------------------------------------------
def restore_system(zipfile: str, source_dir: str, enc_dir: str) -> None:
    """
    Restores the system from a backup zip file.

    - Extracts metadata and encrypted folders.
    - Restores .shadowmeta to the correct location.
    - Restores encrypted folder to user-defined location and hides it.
    - Scans the source folder, encrypts each file into the restored shadow folder,
      and appends a timestamp to each encrypted filename.
    """
    print("RESTORE command engaged...")

    if not os.path.isfile(zipfile):
        print("Backup zip file not found.")
        return

    # Temporary extraction location
    temp_extract = "/tmp/shadow_restore"
    if os.path.exists(temp_extract):
        shutil.rmtree(temp_extract)
    os.makedirs(temp_extract)
    shutil.unpack_archive(zipfile, temp_extract)

    # Identify the metadata and encrypted folders in the extracted backup
    extracted_dirs = os.listdir(temp_extract)
    meta_src = next((os.path.join(temp_extract, d) for d in extracted_dirs if ".shadowmeta" in d), None)
    enc_src = next((os.path.join(temp_extract, d) for d in extracted_dirs if ".shadowmeta" not in d), None)

    if not meta_src or not enc_src:
        print("Backup zip is missing required folders.")
        return

    # Restore metadata to expected metadata_directory location
    if os.path.exists(metadata_directory):
        shutil.rmtree(metadata_directory)
    shutil.copytree(meta_src, metadata_directory)
    print(f"Metadata restored to: {metadata_directory}")

    # Restore encrypted directory to provided path
    if os.path.exists(enc_dir):
        shutil.rmtree(enc_dir)
    shutil.copytree(enc_src, enc_dir)
    enc_dir = hide_directory(enc_dir)
    print(f"Encrypted folder restored and hidden: {enc_dir}")

    # Ensure source directory exists
    if not os.path.exists(source_dir):
        os.makedirs(source_dir)
        os.chmod(source_dir, 0o777)
        print(f"Created source directory: {source_dir}")

    # Update config with new absolute paths
    config = load_configuration()
    config["source_directory"] = os.path.abspath(source_dir)
    config["encrypted_directory"] = os.path.abspath(enc_dir)
    save_configuration(config)

    # Reprocess source files into restored shadow folder with restored timestamp suffix
    file_enc_key = bytes.fromhex(config["file_enc_key"])
    timestamp = datetime.datetime.now().strftime("%Y_%m_%d-%H:%M")

    for f in os.listdir(source_dir):
        src_file = os.path.join(source_dir, f)
        if os.path.isfile(src_file):
            print(f"Restoring file: {f}")
            with open(src_file, "rb") as sf:
                data = sf.read()
            restored_name = f"{f}-restored-{timestamp}"
            enc_file = os.path.join(enc_dir, restored_name + ".enc")
            per_file_key = derive_file_encryption_key(file_enc_key, restored_name)
            encrypt_file(src_file, enc_file, per_file_key)
            set_file_read_only(enc_file)
            store_file_hash(enc_file, data, per_file_key)

    # Finalise shadowfolder security
    set_directory_read_only(enc_dir)
    set_directory_immutable(enc_dir)

    # Log restoration
    master_key = bytes.fromhex(config["file_enc_key"])
    append_log_entry(log_file, master_key, "Command", "System restored from backup.")
    print("RESTORE COMPLETED SUCCESSFULLY.")

# -----------------------------------------------------------------
# Teardown System
# -----------------------------------------------------------------
def remove_system() -> None:
    """
    Securely deletes the encrypted and metadata directories.

    This function removes all files and subdirectories within the encrypted and metadata directories,
    and then removes the directories themselves. It logs the removal operation using the centralized
    logging functions.
    """
    print("REMOVE command engaged...")

    # Load the configuration if the configuration file exists; otherwise, set config to None.
    config = load_configuration() if os.path.exists(config_file) else None
    # Retrieve the encrypted directory from the configuration if available.
    enc_dir = config["encrypted_directory"] if config and "encrypted_directory" in config else None

    if enc_dir and os.path.exists(enc_dir):
        # Remove the immutable flag from the encrypted directory to allow modifications.
        remove_directory_immutable(enc_dir)
        # Walk through the encrypted directory tree, processing from the deepest level upward.
        for root, dirs, files in os.walk(enc_dir, topdown=False):
            for name in files:
                # Securely delete each file in the directory.
                secure_delete(os.path.join(root, name))
            for name in dirs:
                try:
                    # Attempt to remove each subdirectory.
                    os.rmdir(os.path.join(root, name))
                except Exception as e:
                    print(f"Error removing directory {name}: {e}")
        try:
            # Attempt to remove the top-level encrypted directory.
            os.rmdir(enc_dir)
            print(f"Encrypted directory {enc_dir} removed.")
        except Exception as e:
            print(f"Error removing encrypted directory {enc_dir}: {e}")
    else:
        print("Encrypted directory not found.")

    # Process the metadata directory similarly.
    if os.path.exists(metadata_directory):
        for root, dirs, files in os.walk(metadata_directory, topdown=False):
            for name in files:
                secure_delete(os.path.join(root, name))
            for name in dirs:
                try:
                    os.rmdir(os.path.join(root, name))
                except Exception as e:
                    print(f"Error removing directory {name}: {e}")
        try:
            os.rmdir(metadata_directory)
            print(f"Metadata directory {metadata_directory} removed.")
        except Exception as e:
            print(f"Error removing metadata directory {metadata_directory}: {e}")
    else:
        print("Metadata directory not found.")

    # Reload the configuration to obtain the master key.
    config = load_configuration()
    master_key = bytes.fromhex(config["file_enc_key"])
    # Log the system removal event.
    append_log_entry(log_file, master_key, "Command", "System removed (teardown) executed")

# -----------------------------------------------------------------
# Configuration Management
# -----------------------------------------------------------------
def save_configuration(config_data: dict) -> None:
    """
    Encrypts and saves the configuration to the configuration file.

    The function updates the configuration with the current version, converts it to JSON,
    and encrypts it using either an environment-provided key or a derived key from a passphrase.
    The encrypted configuration is then written to the configuration file.
    """
    # Update the configuration data with the current version.
    config_data["version"] = CONFIG_VERSION
    # Convert the configuration dictionary to a JSON-formatted byte string.
    plaintext = json.dumps(config_data).encode('utf-8')

    # Attempt to retrieve an encryption key from the environment.
    env_key = os.environ.get("CONFIG_ENC_KEY")
    if env_key:
        try:
            key = base64.b64decode(env_key)
            if len(key) != 32:
                raise ValueError("CONFIG_ENC_KEY must decode to 32 bytes.")
        except Exception as e:
            print(f"Error decoding CONFIG_ENC_KEY: {e}")
            sys.exit(1)
    else:
        # If no environment key is provided, use the cached key or prompt for a new passphrase.
        key = get_cached_key() or prompt_for_new_passphrase()

    # Encrypt the configuration JSON bytes using the derived or provided key.
    encrypted_config = encrypt_bytes(plaintext, key)
    # Write the encrypted configuration to the configuration file.
    with open(config_file, "wb") as f:
        f.write(encrypted_config)
    print(f"Encrypted configuration saved at: {config_file}")

def load_configuration() -> dict:
    """
    Loads and decrypts the configuration from the configuration file.

    If the configuration file is not found, the function advises to run the deployment command
    and then exits the program. The function uses either an environment-provided key or prompts
    the user for the existing passphrase to decrypt the configuration.
    """
    if not os.path.exists(config_file):
        print("Configuration not found. Please run --deploy first.")
        sys.exit(1)

    # Read the encrypted configuration from the configuration file.
    with open(config_file, "rb") as f:
        encrypted_config = f.read()

    # Attempt to retrieve an encryption key from the environment.
    env_key = os.environ.get("CONFIG_ENC_KEY")
    if env_key:
        try:
            key = base64.b64decode(env_key)
            if len(key) != 32:
                raise ValueError("CONFIG_ENC_KEY must decode to 32 bytes.")
        except Exception as e:
            print(f"Error decoding CONFIG_ENC_KEY: {e}")
            sys.exit(1)
    else:
        # If no environment key is provided, prompt for the existing passphrase.
        key = prompt_for_existing_passphrase(encrypted_config)

    try:
        # Decrypt the configuration using the provided or derived key.
        plaintext = decrypt_bytes(encrypted_config, key)
    except Exception as e:
        print(f"Error decrypting configuration file: {e}")
        sys.exit(1)

    # Decode the plaintext and convert the JSON string back into a dictionary.
    config_data = json.loads(plaintext.decode('utf-8'))
    print("Configuration loaded successfully.")
    return config_data

# -----------------------------------------------------------------
# Deployment and Initial Setup
# -----------------------------------------------------------------
def deploy_system(source_dir: str, encrypted_dir: str) -> None:
    print("DEPLOY command engaged...")

    # Convert source and encrypted directory paths to absolute paths.
    abs_source = os.path.abspath(source_dir)
    abs_encrypted = os.path.abspath(encrypted_dir)

    # Create the source directory if it does not exist, and set full permissions.
    if not os.path.exists(abs_source):
        os.makedirs(abs_source)
        os.chmod(abs_source, 0o777)
        print(f"Created source directory: {abs_source}")
    else:
        print(f"Source directory exists: {abs_source}")

    # Create the encrypted directory if it does not exist.
    if not os.path.exists(abs_encrypted):
        os.makedirs(abs_encrypted)
        print(f"Created encrypted directory: {abs_encrypted}")
    else:
        print(f"Encrypted directory exists: {abs_encrypted}")

    # Hide the encrypted directory (rename it to have a leading dot).
    abs_encrypted = hide_directory(abs_encrypted)

    # Ensure the script is running on a Linux system.
    if not is_linux_system():
        print("Error: This script requires Linux.")
        sys.exit(1)

    # Verify that the encrypted directory is on a supported filesystem.
    if not check_filesystem(abs_encrypted):
        print("Deployment aborted due to unsupported filesystem.")
        sys.exit(1)

    # Create the metadata directory if it does not exist.
    if not os.path.exists(metadata_directory):
        os.makedirs(metadata_directory)
        print(f"Created metadata directory: {metadata_directory}")
    else:
        print(f"Metadata directory exists: {metadata_directory}")

    # Initialise log ledger and hash backup file (create empty files).
    for path in [log_file, hash_backup_file]:
        with open(path, "w") as f:
            f.write("")
    print("Initialized log ledger and hash backup file.")

    # Generate a new file encryption key and cache the new passphrase.
    file_enc_key = generate_encryption_key()
    file_enc_key_hex = file_enc_key.hex()
    _ = prompt_for_new_passphrase()

    # Prepare the configuration data.
    config_data = {
        "source_directory": abs_source,
        "encrypted_directory": abs_encrypted,
        "deployment_time": datetime.datetime.now().isoformat(),
        "file_enc_key": file_enc_key_hex
    }
    # Save the encrypted configuration.
    save_configuration(config_data)

    # List the items in the source directory.
    items = os.listdir(abs_source)
    if not items:
        print("No files found in source directory.")
    else:
        print(f"Found {len(items)} item(s) in source directory.")

    # Reload the configuration and retrieve the master key.
    config = load_configuration()
    master_key = bytes.fromhex(config["file_enc_key"])
    append_log_entry(log_file, master_key, "Command", "Deploy command invoked.")

    # Process each file in the source directory.
    for item in items:
        src_file = os.path.join(abs_source, item)
        if os.path.isfile(src_file):
            print(f"Processing file: {item}")
            enc_file = os.path.join(abs_encrypted, item + ".enc")
            with open(src_file, "rb") as f:
                data = f.read()
            # Derive a per-file key using the master key and the filename.
            per_file_key = derive_file_encryption_key(file_enc_key, item)
            # Compute the SHA-256 hash of the file.
            file_hash = compute_sha256(data).hex()
            print(f"Encrypting {item} with hash (SHA-256: {file_hash})")
            # Encrypt the source file and write the encrypted data.
            encrypt_file(src_file, enc_file, per_file_key)
            # Set the encrypted file to read-only.
            set_file_read_only(enc_file)
            # Store the encrypted hash in the file's extended attributes and back it up.
            store_file_hash(enc_file, data, per_file_key)
            # Retrieve the file statistics (size and modification time).
            size_bytes, _ = get_file_stats(src_file)
            # Append a log entry for the file addition event.
            append_log_entry(
                log_file, master_key, "File", "",
                file_event="File Added",
                file_name=item,
                size=f"{size_bytes} bytes",
                file_format=os.path.splitext(item)[1],
                file_hash=file_hash
            )

    # Set the encrypted directory as read-only and apply the immutable flag.
    set_directory_read_only(abs_encrypted)
    set_directory_immutable(abs_encrypted)
    append_log_entry(log_file, master_key, "Command", "Deployment completed and encrypted directory secured.")
    print("DEPLOYMENT SUCCESSFUL.")

# -----------------------------------------------------------------
# Update System
# -----------------------------------------------------------------
def update_system(auto_mode: bool = False) -> None:
    print("UPDATE/REVIEW command engaged...")

    # Load the configuration and retrieve source and encrypted directories.
    config = load_configuration()
    src_dir = config["source_directory"]
    enc_dir = config["encrypted_directory"]

    # Retrieve the master file encryption key.
    file_enc_key = bytes.fromhex(config["file_enc_key"])
    master_key = file_enc_key
    append_log_entry(log_file, master_key, "Command", "Update command invoked")

    # Remove the immutable flag from the encrypted directory and change its permissions to allow updates.
    remove_directory_immutable(enc_dir)
    os.chmod(enc_dir, 0o755)
    append_log_entry(log_file, master_key, "Command", "Removed immutable flag for update")

    # Determine the set of files in the source and encrypted directories.
    src_files = {f for f in os.listdir(src_dir) if os.path.isfile(os.path.join(src_dir, f))}
    # Encrypted files have a ".enc" extension; remove the extension for comparison.
    enc_files = {f[:-4] for f in os.listdir(enc_dir) if f.endswith(".enc")}

    # Identify new files (present in source but not in encrypted),
    # deleted files (present in encrypted but not in source) and modified files.
    new_files = src_files - enc_files
    deleted_files = enc_files - src_files
    modified_files = set()

    # For files present in both directories, check if they have been modified.
    for f in src_files & enc_files:
        src_file = os.path.join(src_dir, f)
        enc_file = os.path.join(enc_dir, f + ".enc")
        with open(src_file, "rb") as sf:
            src_data = sf.read()
        # Derive the per-file key from the master key and filename.
        per_file_key = derive_file_encryption_key(file_enc_key, f)
        try:
            # Attempt to decrypt the encrypted file.
            enc_data = decrypt_file_contents(enc_file, per_file_key)
        except Exception as e:
            print(f"Error decrypting {enc_file}: {e}")
            enc_data = None
        # If decryption fails or data differs, mark the file as modified.
        if enc_data is None or src_data != enc_data:
            modified_files.add(f)

    print(f"\nNew files detected: {new_files}")
    print(f"Modified files detected: {modified_files}")
    print(f"Deleted files detected: {deleted_files}")

    # Process new files detected in the source directory.
    for f in sorted(new_files):
        src_file = os.path.join(src_dir, f)
        print(f"\nNew file detected: {f}")
        size_bytes, mtime = get_file_stats(src_file)
        print(f"Metadata: {f} | {size_bytes} bytes | {mtime}")
        # If auto_mode is True, automatically accept; otherwise prompt user.
        choice = 'y' if auto_mode else input("Add this file? (y/n): ").strip().lower()
        if choice == 'y':
            enc_file = os.path.join(enc_dir, f + ".enc")
            with open(src_file, "rb") as sf:
                data = sf.read()
            per_file_key = derive_file_encryption_key(file_enc_key, f)
            file_hash = compute_sha256(data).hex()
            print(f"Encrypting {f} with new hash (SHA-256: {file_hash})")
            # Encrypt the file and store the hash.
            encrypt_file(src_file, enc_file, per_file_key)
            set_file_read_only(enc_file)
            store_file_hash(enc_file, data, per_file_key)
            append_log_entry(
                log_file, master_key, "File", "",
                file_event="File Added",
                file_name=f,
                size=f"{size_bytes} bytes",
                file_format=os.path.splitext(f)[1],
                file_hash=file_hash
            )
        else:
            append_log_entry(log_file, master_key, "Command", f"Skipped adding file {f}")

    # Process modified files.
    for f in sorted(modified_files):
        src_file = os.path.join(src_dir, f)
        enc_file = os.path.join(enc_dir, f + ".enc")
        print(f"\nModified file detected: {f}")
        size_bytes, mtime = get_file_stats(src_file)
        print(f"Source metadata: {f} | {size_bytes} bytes | {mtime}")
        if os.path.exists(enc_file):
            enc_size, enc_mtime = get_file_stats(enc_file)
            print(f"Encrypted metadata: {f}.enc | {enc_size} bytes | {enc_mtime}")
        choice = 'y' if auto_mode else input("Update this file? (y/n): ").strip().lower()
        if choice == 'y':
            if os.path.exists(enc_file):
                make_file_writable(enc_file)
            with open(src_file, "rb") as sf:
                data = sf.read()
            per_file_key = derive_file_encryption_key(file_enc_key, f)
            file_hash = compute_sha256(data).hex()
            print(f"Encrypting {f} with updated hash (SHA-256: {file_hash})")
            encrypt_file(src_file, enc_file, per_file_key)
            set_file_read_only(enc_file)
            store_file_hash(enc_file, data, per_file_key)
            append_log_entry(
                log_file, master_key, "File", "",
                file_event="File Modified",
                file_name=f,
                size="(old) > (new)",
                file_format="(old) > (new)",
                file_hash="(old) > " + file_hash
            )
        else:
            append_log_entry(log_file, master_key, "Command", f"Skipped updating file {f}")

    # Process deleted files.
    for f in sorted(deleted_files):
        enc_file = os.path.join(enc_dir, f + ".enc")
        print(f"\nDeletion detected: Source file '{f}' is missing.")
        choice = 'y' if auto_mode else input("Remove encrypted file? (y/n): ").strip().lower()
        if choice == 'y':
            make_file_writable(enc_file)
            try:
                os.remove(enc_file)
                print(f"Encrypted file '{enc_file}' removed.")
                append_log_entry(
                    log_file, master_key, "File", "",
                    file_event="File Removed",
                    file_name=f,
                    size="N/A",
                    file_format="N/A",
                    file_hash="N/A"
                )
            except OSError as e:
                print(f"Error removing encrypted file '{enc_file}': {e}")
        else:
            append_log_entry(log_file, master_key, "Command", f"Kept encrypted file for deleted source file '{f}'")

    # Ensure all encrypted files are set to read-only.
    for f in os.listdir(enc_dir):
        if f.endswith(".enc"):
            set_file_read_only(os.path.join(enc_dir, f))

    # Set the encrypted directory as read-only and reapply the immutable flag.
    set_directory_read_only(enc_dir)
    set_directory_immutable(enc_dir)
    append_log_entry(log_file, master_key, "Command", "Update applied and encrypted directory secured.")
    print("UPDATE/REVIEW COMPLETED SUCCESSFULLY.")

# -----------------------------------------------------------------
# Dump Single File
# -----------------------------------------------------------------
def dump_single_file(file_name: str, dump_path: str) -> None:
    print("DUMP command engaged...")
    # Load the current configuration.
    config = load_configuration()
    # Retrieve the encrypted directory from the configuration.
    enc_dir = config["encrypted_directory"]
    # Retrieve the master file encryption key and convert it from hexadecimal format to bytes.
    file_enc_key = bytes.fromhex(config["file_enc_key"])
    master_key = file_enc_key
    # Log that the dump command has been invoked for the specified file.
    append_log_entry(log_file, master_key, "Command", f"Dump command invoked for {file_name}")
    # Construct the full path to the encrypted file (assuming a ".enc" extension).
    enc_file = os.path.join(enc_dir, file_name + ".enc")
    # Check if the encrypted file exists; if not, notify the user and exit the function.
    if not os.path.exists(enc_file):
        print(f"Encrypted file for {file_name} not found.")
        return
    # Derive a per-file encryption key using the master key and the file name.
    per_file_key = derive_file_encryption_key(file_enc_key, file_name)
    try:
        # Attempt to decrypt the encrypted file using the derived key.
        data = decrypt_file_contents(enc_file, per_file_key)
    except Exception as e:
        print(f"Error decrypting {file_name}: {e}")
        return
    # Create the dump directory if it does not exist.
    if not os.path.exists(dump_path):
        os.makedirs(dump_path)
        print(f"Created dump directory: {dump_path}")
    # Construct the destination path for the decrypted file.
    dest = os.path.join(dump_path, file_name)
    # Write the decrypted file data to the destination file.
    with open(dest, "wb") as f:
        f.write(data)
    os.chmod(dest, 0o777)
    # Set full read, write, and execute permissions to make the dumped file fully accessible.
    set_file_read_only(dest)
    print(f"Dumped decrypted file to {dest}")

# -----------------------------------------------------------------
# Clone All Files
# -----------------------------------------------------------------
def clone_all_files(dump_path: str) -> None:
    print("CLONE command engaged...")
    # Load the current configuration.
    config = load_configuration()
    # Retrieve the encrypted directory path from the configuration.
    enc_dir = config["encrypted_directory"]
    # Retrieve and convert the master file encryption key.
    file_enc_key = bytes.fromhex(config["file_enc_key"])
    master_key = file_enc_key
    # Log that the clone command has been invoked.
    append_log_entry(log_file, master_key, "Command", "Clone command invoked")

    # Create the dump directory if it does not already exist.
    if not os.path.exists(dump_path):
        os.makedirs(dump_path)
        print(f"Created dump directory: {dump_path}")

    # Iterate through files in the encrypted directory.
    for enc in os.listdir(enc_dir):
        # Process only files with a '.enc' extension.
        if enc.endswith(".enc"):
            # Remove the '.enc' extension to obtain the original file name.
            fname = enc[:-4]
            # Derive the per-file key using the master encryption key and filename.
            per_file_key = derive_file_encryption_key(file_enc_key, fname)
            try:
                # Decrypt the encrypted file using the derived key.
                data = decrypt_file_contents(os.path.join(enc_dir, enc), per_file_key)
            except Exception as e:
                print(f"Error decrypting {fname}: {e}")
                continue
            # Define the destination path for the decrypted file.
            dest = os.path.join(dump_path, fname)
            # Write the decrypted file contents to the destination path.
            with open(dest, "wb") as f:
                f.write(data)
            os.chmod(dest, 0o777)
            # Set full read, write, and execute permissions to make the dumped file fully accessible.
            set_file_read_only(dest)
    print(f"Cloned all decrypted files to {dump_path}")

# -----------------------------------------------------------------
# Verify Single File
# -----------------------------------------------------------------
def verify_single_file(file_name: str) -> None:
    print("VERIFY command engaged...")

    # Load the configuration and retrieve the source and encrypted directories.
    config = load_configuration()
    src_dir = config["source_directory"]
    enc_dir = config["encrypted_directory"]

    # Retrieve and convert the master file encryption key.
    file_enc_key = bytes.fromhex(config["file_enc_key"])
    master_key = file_enc_key

    # Log that the verify command has been invoked for the specified file.
    append_log_entry(log_file, master_key, "Command", f"Verify command invoked for {file_name}")

    # Construct the full paths for the source and encrypted file.
    src_file = os.path.join(src_dir, file_name)
    enc_file = os.path.join(enc_dir, file_name + ".enc")

    # Check if the source file exists.
    if not os.path.exists(src_file):
        print(f"Source file {file_name} does not exist.")
        return

    # Check if the corresponding encrypted file exists.
    if not os.path.exists(enc_file):
        print(f"Encrypted file for {file_name} does not exist.")
        return

    # Read the contents of the source file.
    with open(src_file, "rb") as f:
        src_data = f.read()

    # Derive the per-file encryption key using the master key and the file name.
    per_file_key = derive_file_encryption_key(file_enc_key, file_name)

    try:
        # Attempt to decrypt the encrypted file using the derived key.
        enc_data = decrypt_file_contents(enc_file, per_file_key)
    except Exception as e:
        print(f"Error decrypting {file_name}: {e}")
        return

    # Compute SHA-256 hashes for both the source and decrypted file data.
    src_hash = hashlib.sha256(src_data).hexdigest()
    enc_hash = hashlib.sha256(enc_data).hexdigest()

    # Retrieve the file statistics (size and last modified time) for the source file.
    size_bytes, mtime = get_file_stats(src_file)

    # Display the file metadata and computed hashes.
    print(f"\n{file_name} | {size_bytes} bytes | {mtime}")
    print(f"Source Hash (SHA-256): {src_hash}")
    print(f"Shadow Hash (SHA-256): {enc_hash}")

    # Compare the hashes and display the outcome.
    if src_hash == enc_hash:
        print("Outcome     : Hashes match")
    else:
        print("Outcome     : Hashes do NOT match")

# -----------------------------------------------------------------
# Audit All Files
# -----------------------------------------------------------------
def audit_all_files() -> None:
    print("AUDIT command engaged...")

    # Load the configuration and retrieve source and encrypted directory paths.
    config = load_configuration()
    src_dir = config["source_directory"]
    enc_dir = config["encrypted_directory"]

    # Retrieve and convert the master encryption key.
    file_enc_key = bytes.fromhex(config["file_enc_key"])
    master_key = file_enc_key

    # Log that the audit command has been invoked.
    append_log_entry(log_file, master_key, "Command", "Audit command invoked")

    print("\n===== AUDIT REPORT =====")

    # Iterate through each file in the source directory.
    for fname in sorted(os.listdir(src_dir)):
        src_file = os.path.join(src_dir, fname)
        enc_file = os.path.join(enc_dir, fname + ".enc")

        # Process only if both source and encrypted files exist.
        if os.path.isfile(src_file) and os.path.exists(enc_file):
            # Read the source file contents.
            with open(src_file, "rb") as f:
                src_data = f.read()

            # Derive the per-file key using the master key and file name.
            per_file_key = derive_file_encryption_key(file_enc_key, fname)

            try:
                # Attempt to decrypt the corresponding encrypted file.
                enc_data = decrypt_file_contents(enc_file, per_file_key)
            except Exception as e:
                print(f"{fname}: Error decrypting: {e}")
                continue

            # Compute hashes for source and decrypted data.
            src_hash = hashlib.sha256(src_data).hexdigest()
            enc_hash = hashlib.sha256(enc_data).hexdigest()

            # Retrieve the size and modification time of the source file.
            size_bytes, mtime = get_file_stats(src_file)

            # Display audit details.
            print(f"{fname} | {size_bytes} bytes | {mtime}")
            print(f"Source Hash (SHA-256): {src_hash}")
            print(f"Shadow Hash (SHA-256): {enc_hash}")

            if src_hash == enc_hash:
                print("Outcome     : Hashes match\n")
            else:
                print("Outcome     : Hashes do NOT match\n")

    print("========================")

    # Log that the audit process has completed.
    append_log_entry(log_file, master_key, "Command", "Audit completed")

# -----------------------------------------------------------------
# Show File Metadata
# -----------------------------------------------------------------
def show_metadata(file_name: str) -> None:
    print("META command engaged...")

    # Load configuration and retrieve the encrypted directory path.
    config = load_configuration()
    enc_dir = config["encrypted_directory"]

    # Retrieve and convert the master file encryption key.
    file_enc_key = bytes.fromhex(config["file_enc_key"])
    master_key = file_enc_key

    # Log that the META command has been invoked.
    append_log_entry(log_file, master_key, "Command", f"Meta command invoked for {file_name}")

    # Build the path to the encrypted file.
    enc_file = os.path.join(enc_dir, file_name + ".enc")

    # Check if the encrypted file exists.
    if not os.path.exists(enc_file):
        print(f"Encrypted file for {file_name} not found.")
        return

    # Retrieve file size and last modification time.
    size_bytes, mtime = get_file_stats(enc_file)

    # Derive the per-file encryption key.
    per_file_key = derive_file_encryption_key(file_enc_key, file_name)

    # Attempt to retrieve and decrypt the stored hash from extended attributes.
    try:
        stored_hash = xattr.getxattr(enc_file, "user.shadowhash")
        decrypted_hash = decrypt_bytes(stored_hash, per_file_key).decode()
    except Exception:
        decrypted_hash = "N/A"

    # Display metadata details.
    print("\n===== FILE METADATA =====")
    print(f"{file_name}.enc | {size_bytes} bytes | {mtime}")
    print(f"Hash (SHA-256): {decrypted_hash}")
    print("=========================")

# -----------------------------------------------------------------
# Change Configuration Passphrase
# -----------------------------------------------------------------
def change_passphrase() -> None:
    print("PASS-PHRASE command engaged...")

    # Load the existing configuration.
    config = load_configuration()

    # Ensure that the current passphrase is verified or re-entered if not cached.
    _ = get_cached_key() or prompt_for_existing_passphrase(open(config_file, "rb").read())

    # Prompt the user to set a new passphrase and derive a new encryption key.
    _ = prompt_for_new_passphrase()

    # Save the configuration again using the new encryption key.
    save_configuration(config)

    # Reload the configuration to confirm that it is still accessible.
    config = load_configuration()
    master_key = bytes.fromhex(config["file_enc_key"])

    # Log the completion of the passphrase change.
    append_log_entry(log_file, master_key, "Command", "Passphrase rotation completed")
    print("Passphrase rotation completed.")

# -----------------------------------------------------------------
# Panic Recovery Dump
# -----------------------------------------------------------------
def panic_mode(config_dir: str, shadow_dir: str, dump_dir: str, passphrase: str) -> None:
    """
    Emergency decryption dump using retrieved configuration and shadow folder.

    This command is used when system recovery is required after a breach or disaster.
    It decrypts all files in the shadow folder using the provided passphrase and dumps
    them unencrypted into the specified directory, bypassing the need for a source folder.
    """
    print("PANIC command engaged...")

    # Step 1: Load the encrypted configuration file from the specified config directory.
    config_path = os.path.join(config_dir, "config.json")
    if not os.path.exists(config_path):
        print("Error: config.json not found in specified config folder.")
        return

    try:
        with open(config_path, "rb") as f:
            encrypted_config = f.read()
            # Successfully read the encrypted configuration.
    except Exception as e:
        print(f"Error reading config.json: {e}")
        return

    # Step 2: Load the salt used for passphrase-based configuration decryption.
    salt_path = os.path.join(config_dir, "config_salt.bin")
    if not os.path.exists(salt_path):
        print("Error: config_salt.bin not found in specified config folder.")
        return

    try:
        with open(salt_path, "rb") as f:
            salt = f.read()
            # Successfully loaded the salt value.
    except Exception as e:
        print(f"Error reading salt file: {e}")
        return

    # Step 3: Derive the configuration key using the provided passphrase and the loaded salt.
    try:
        # Initialize the key derivation function using PBKDF2HMAC with SHA256.
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        # Derive the key from the passphrase.
        key = kdf.derive(passphrase.encode())
        # Use the derived key to decrypt the encrypted configuration.
        plaintext = decrypt_bytes(encrypted_config, key)
        # Parse the decrypted configuration as JSON.
        config = json.loads(plaintext.decode('utf-8'))
        print("Configuration successfully decrypted.")
    except Exception as e:
        print(f"Failed to decrypt config.json: {e}")
        return

    # Step 4: Extract the file encryption key from the decrypted configuration.
    # The file encryption key is stored in hexadecimal format within the config.
    file_enc_key = bytes.fromhex(config["file_enc_key"])
    processed = 0  # Counter for successfully decrypted files.
    failed = 0     # Counter for files that failed decryption.

    # Step 5: Validate that the shadow directory (folder with encrypted files) exists.
    if not os.path.exists(shadow_dir):
        print("Error: Shadow folder path does not exist.")
        return

    # Step 6: Create the dump directory if it does not already exist.
    # The dump directory is where decrypted files will be stored.
    if not os.path.exists(dump_dir):
        os.makedirs(dump_dir)
        print(f"Created dump directory: {dump_dir}")

    print("Processing encrypted files...")

    # Step 7: Iterate through each file in the shadow folder.
    for f in os.listdir(shadow_dir):
        # Process only files that end with the '.enc' extension.
        if f.endswith(".enc"):
            enc_path = os.path.join(shadow_dir, f)
            file_name = f[:-4]  # Remove the '.enc' extension to obtain the original filename.
            try:
                # Derive a unique encryption key for the file using the master file encryption key
                # and the original file name as salt.
                per_file_key = derive_file_encryption_key(file_enc_key, file_name)
                # Attempt to decrypt the file using the derived per-file key.
                data = decrypt_file_contents(enc_path, per_file_key)

                # Construct the destination path within the dump directory using the original file name.
                dest_path = os.path.join(dump_dir, file_name)
                # Write the decrypted data to the destination file.
                with open(dest_path, "wb") as out:
                    out.write(data)

                # Set the destination file's permissions to full read/write/execute for emergency access.
                os.chmod(dest_path, 0o777)
                print(f"Decrypted and dumped: {file_name}")
                processed += 1  # Increment the successful decryption counter.
            except Exception as e:
                # Log an error if decryption fails for a file.
                print(f"Failed to decrypt {file_name}: {e}")
                failed += 1  # Increment the failure counter.

    # Step 8: Display a summary of the panic operation, including counts of processed and failed files.
    print(f"\nPANIC completed. Files decrypted: {processed}, Failed: {failed}")

# -----------------------------------------------------------------
# Unpack Recovery Dump
# -----------------------------------------------------------------
def unpack_backup_zip(zip_path: str, dump_path: str) -> None:
    """
    Extracts and decrypts files from a backup zip archive into the specified dump directory.

    This function is used to recover a backup that contains both the encrypted configuration
    (inside a .shadowmeta folder) and the encrypted files (in the shadow folder). The routine:
      1. Checks the existence of the provided zip file.
      2. Extracts the archive into a temporary directory.
      3. Searches the extracted tree for the .shadowmeta folder (which holds the configuration)
         and the folder containing encrypted files (.enc).
      4. Loads and decrypts the configuration file using the embedded salt from the backup.
      5. Reinstates the file encryption key and then decrypts each encrypted file from the shadow folder.
      6. Writes the decrypted files into the specified dump directory and sets full access permissions.
    """
    print("UNPACK command engaged...")

    # Step 1: Check if the backup zip file exists.
    if not os.path.isfile(zip_path):
        print("Provided zip file does not exist.")
        return

    # Step 2: Extract the zip file to a temporary directory.
    temp_dir = tempfile.mkdtemp(prefix="shadow_unpack_")
    print(f"Extracting backup zip to temporary directory: {temp_dir}")
    try:
        shutil.unpack_archive(zip_path, temp_dir)
        # Backup zip extracted successfully.
    except Exception as e:
        print(f"Failed to extract zip file: {e}")
        return

    # Step 3: Locate the .shadowmeta folder and the encrypted shadow folder inside the extracted structure.
    meta_path = None
    shadow_path = None

    # Traverse the extracted directory tree.
    for root, dirs, _ in os.walk(temp_dir):
        for d in dirs:
            # Identify the .shadowmeta folder which holds the configuration files.
            if d == ".shadowmeta":
                meta_path = os.path.join(root, d)
            # Identify a folder containing .enc files, which are the encrypted files.
            elif any(f.endswith(".enc") for f in os.listdir(os.path.join(root, d))):
                shadow_path = os.path.join(root, d)

    # Abort the operation if either the .shadowmeta or the shadow folder is missing.
    if not meta_path or not shadow_path:
        print("Failed to locate .shadowmeta or shadow folder in the backup.")
        return

    # Step 4: Load and decrypt the configuration file using the salt embedded in the backup.
    config_file_path = os.path.join(meta_path, "config.json")
    if not os.path.exists(config_file_path):
        print("Config file not found in the backup.")
        return

    # Read the encrypted configuration file.
    with open(config_file_path, "rb") as f:
        encrypted_config = f.read()

    # Temporarily update the salt_file reference to point to the salt file in the backup.
    global salt_file
    original_salt_path = salt_file  # Save the current salt file location.
    salt_file = os.path.join(meta_path, "config_salt.bin")

    # Prompt for the passphrase to unlock the backup configuration and derive the key.
    key = prompt_for_existing_passphrase(encrypted_config)
    try:
        # Decrypt the encrypted configuration using the derived key.
        decrypted = decrypt_bytes(encrypted_config, key)
        # Parse the decrypted JSON configuration.
        config = json.loads(decrypted.decode())
    except Exception as e:
        print(f"Could not decrypt configuration: {e}")
        salt_file = original_salt_path  # Restore the original salt file path.
        return

    # Retrieve the file encryption key from the decrypted configuration.
    file_enc_key = bytes.fromhex(config["file_enc_key"])
    salt_file = original_salt_path  # Restore the original salt file reference.

    # Step 5: Create the destination dump folder if it does not already exist.
    if not os.path.exists(dump_path):
        os.makedirs(dump_path)
        print(f"Created dump path: {dump_path}")

    # Step 6: Decrypt and unpack each encrypted file from the shadow folder to the dump directory.
    for f in os.listdir(shadow_path):
        if f.endswith(".enc"):
            fname = f[:-4]  # Remove the '.enc' extension to get the original file name.
            src_path = os.path.join(shadow_path, f)
            try:
                # Derive a unique decryption key for the file using its name.
                per_file_key = derive_file_encryption_key(file_enc_key, fname)
                # Decrypt the file contents using the derived key.
                data = decrypt_file_contents(src_path, per_file_key)
                # Define the destination path in the dump folder.
                dest_path = os.path.join(dump_path, fname)
                # Write the decrypted data to the destination file.
                with open(dest_path, "wb") as out:
                    out.write(data)
                # Set the file permissions to allow full access.
                os.chmod(dest_path, 0o777)
                print(f"Unpacked {fname} to {dest_path}")
            except Exception as e:
                print(f"Failed to decrypt {f}: {e}")

    print("UNPACK COMPLETED SUCCESSFULLY.")

# -----------------------------------------------------------------
# Main Command Line Interface
# -----------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Deployment, Synchronization, and Forensic Analysis Script with Enhanced Security and Usability Features.\n\n"
            "Commands:\n"
            "  --deploy <SOURCE_DIRECTORY> <ENCRYPTED_DIRECTORY>   : Initialize the system by setting up source and encrypted directories.\n"
            "  --review                                           : Run in interactive update mode to manually approve file changes.\n"
            "  --update                                           : Run in automatic update mode to auto-confirm all file changes.\n"
            "  --dump <FILE_NAME> <DUMP_DIRECTORY>                : Decrypt a specified encrypted file and dump it to the designated directory.\n"
            "  --clone <DUMP_DIRECTORY>                           : Decrypt and clone all encrypted files into the specified dump directory.\n"
            "  --verify <FILE_NAME>                               : Verify the integrity of a specified file by comparing its hash with the stored value.\n"
            "  --audit                                            : Perform a comprehensive audit by verifying all source files against encrypted files.\n"
            "  --meta <FILE_NAME>                                 : Display metadata (e.g., size, modification time, stored SHA-256 hash) for the specified file.\n"
            "  --log                                              : Decrypt and display the log ledger of system events.\n"
            "  --passphrase                                       : Rotate or change the configuration passphrase and re-encrypt the configuration.\n"
            "  --status                                           : Display a summary of system status and deployment details.\n"
            "  --backup <DUMP_DIRECTORY>                          : Create a zip archive backup of both metadata and encrypted directories in the target location.\n"
            "  --restore <ZIPFILE> <SOURCE_DIRECTORY> <ENCRYPTED_DIRECTORY> : Restore the system from a backup zip, updating both the source and encrypted directories.\n"
            "  --report                                           : Generate and display a forensic report detailing deployment, system status, file metadata, and logs.\n"
            "  --remove                                           : Securely delete the encrypted and metadata directories (system teardown).\n"
            "  --destroy <FILE_PATH>                              : Securely shred a specified file, ensuring no traces remain.\n"
            "  --panic <CONFIG_DIRECTORY> <SHADOW_DIRECTORY> <DUMP_DIRECTORY> <PASSPHRASE> : Enter emergency recovery mode to dump decrypted files from the shadow folder using a recovered configuration and passphrase.\n"
            "  --unpack <ZIP_FILE> <DUMP_DIRECTORY>               : Extract and decrypt files from a backup zip archive into the specified dump directory.\n"
        )
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--deploy", nargs=2, metavar=("SOURCE_DIRECTORY", "ENCRYPTED_DIRECTORY"),
                       help="Deploy: initialise system with source and encrypted directories.")
    group.add_argument("--review", action="store_true",
                       help="Review: interactively mirror changes (manual approval required).")
    group.add_argument("--update", action="store_true",
                       help="Update: automatically mirror changes (auto-confirm all file changes).")
    group.add_argument("--dump", nargs=2, metavar=("FILE_NAME", "DUMP_DIRECTORY"),
                       help="Dump: decrypt a specified encrypted file to DUMP_DIRECTORY.")
    group.add_argument("--clone", metavar="DUMP_DIRECTORY",
                       help="Clone: decrypt and dump all encrypted files to DUMP_DIRECTORY.")
    group.add_argument("--verify", nargs=1, metavar="FILE_NAME",
                       help="Verify: check a specified file's integrity.")
    group.add_argument("--audit", action="store_true",
                       help="Audit: verify all source files against encrypted files.")
    group.add_argument("--meta", metavar="FILE_NAME",
                       help="Meta: display metadata for the specified encrypted file.")
    group.add_argument("--log", action="store_true",
                       help="Log: display the decrypted log ledger.")
    group.add_argument("--passphrase", action="store_true",
                       help="Passphrase: rotate the configuration passphrase.")
    group.add_argument("--status", action="store_true",
                       help="Status: display system status summary.")
    group.add_argument("--backup", metavar="DUMP_DIRECTORY",
                       help="Backup: create a zip archive backup of metadata and encrypted directories.")
    group.add_argument("--restore", nargs=3, metavar=("ZIPFILE", "SOURCE_DIRECTORY", "ENCRYPTED_DIRECTORY"),
                       help="Restore: restore system from a backup zip archive.")
    group.add_argument("--report", action="store_true",
                       help="Report: display a forensic report on the console.")
    group.add_argument("--remove", action="store_true",
                       help="Remove: securely delete the encrypted and metadata directories (teardown).")
    group.add_argument("--destroy", metavar="FILE_PATH",
                       help="Destroy: securely shred the specified file leaving no traces.")
    group.add_argument("--panic", nargs=4, metavar=("CONFIG_DIRECTORY", "SHADOW_DIRECTORY", "DUMP_DIRECTORY", "PASSPHRASE"),
                       help="Panic: emergency dump of shadow folder using recovered configuration and passphrase.")
    group.add_argument("--unpack", nargs=2, metavar=("ZIP_FILE", "DUMP_DIRECTORY"),
                       help="Unpack: extract and decrypt files from a backup zip into DUMP_DIRECTORY.")

    # Parse the command-line arguments.
    args = parser.parse_args()

    # If the deploy argument is provided, initialize the system using the specified source and encrypted directories.
    if args.deploy:
        deploy_system(args.deploy[0], args.deploy[1])

    # If the review flag is set, invoke an interactive update process that requires manual approval for file changes.
    elif args.review:
        update_system(auto_mode=False)

    # If the update flag is set, invoke an automatic update process that automatically confirms all file changes.
    elif args.update:
        update_system(auto_mode=True)

    # If the dump argument is provided with a file name and dump directory,
    # decrypt the specified encrypted file and dump the plaintext file into the designated directory.
    elif args.dump:
        dump_single_file(args.dump[0], args.dump[1])

    # If the clone argument is provided with a dump directory,
    # decrypt all files in the encrypted directory and copy them into the specified dump directory.
    elif args.clone:
        clone_all_files(args.clone)

    # If the verify argument is provided with a file name,
    # check the integrity of the specified file by comparing its computed hash with the stored (encrypted) hash.
    elif args.verify:
        verify_single_file(args.verify[0])

    # If the audit flag is set, perform an audit by verifying all source files against their corresponding encrypted files.
    elif args.audit:
        audit_all_files()

    # If the meta argument is provided with a file name,
    # display metadata (such as file size, modification time, and stored SHA-256 hash) for that encrypted file.
    elif args.meta:
        show_metadata(args.meta)

    # If the log flag is set, load the configuration, decrypt, and display the encrypted log ledger.
    elif args.log:
        config = load_configuration()
        master_key = bytes.fromhex(config["file_enc_key"])
        display_log_ledger(log_file, master_key)
        # Append a log entry to record that the log ledger was displayed.
        append_log_entry(log_file, master_key, "Command", "Displayed log ledger")

    # If the passphrase flag is set, initiate the passphrase rotation process to change the configuration encryption passphrase.
    elif args.passphrase:
        change_passphrase()

    # If the status flag is set, display a summary of the current system status including directories and file counts.
    elif args.status:
        print_status()

    # If the backup argument is provided with a dump directory,
    # create a zip archive backup of the metadata and encrypted directories in the specified location.
    elif args.backup:
        backup_system(args.backup)

    # If the restore argument is provided with a backup zip file, source directory, and encrypted directory,
    # restore the system from the backup.
    elif args.restore:
        restore_system(args.restore[0], args.restore[1], args.restore[2])

    # If the report flag is set, generate and display a comprehensive forensic report of the deployment and file statuses.
    elif args.report:
        generate_forensic_report()

    # If the remove flag is set, securely delete the encrypted and metadata directories (system teardown).
    elif args.remove:
        remove_system()

    # If the destroy argument is provided with a file path, securely delete (shred) the specified file.
    elif args.destroy:
        destroy_file(args.destroy)

    # If the panic argument is provided with the configuration directory, shadow directory,
    # dump directory, and a passphrase, perform an emergency decryption dump (panic mode) for recovery purposes.
    elif args.panic:
        config_dir, shadow_dir, dump_dir, passphrase = args.panic
        panic_mode(config_dir, shadow_dir, dump_dir, passphrase)

    # If the unpack argument is provided with a backup zip file and dump directory,
    # extract and decrypt the backup files from the zip archive into the specified dump directory.
    elif args.unpack:
        zip_path, dump_path = args.unpack
        unpack_backup_zip(zip_path, dump_path)

    # If none of the expected arguments were provided, display the help message with usage instructions.
    else:
        parser.print_help()

if __name__ == "__main__":
    main()