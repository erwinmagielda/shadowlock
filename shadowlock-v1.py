#!/usr/bin/env python3
import argparse
import base64
import datetime
import hashlib
import hmac
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from getpass import getpass
from typing import Optional

import xattr
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

metadata_directory = os.path.expanduser("~/.shadowmeta")
config_file = os.path.join(metadata_directory, "config.json")
hash_backup_file = os.path.join(metadata_directory, "hash_backup.json")
log_file = os.path.join(metadata_directory, "log.enc")
salt_file = os.path.join(metadata_directory, "config_salt.bin")

CONFIG_VERSION = "1.0.0"
CACHE_TIMEOUT = 600

cached_key: Optional[bytes] = None
cached_timestamp: Optional[float] = None


def get_cached_key() -> Optional[bytes]:
    global cached_key, cached_timestamp
    if cached_key and cached_timestamp:
        elapsed_time = time.time() - cached_timestamp
        print(f"Cached key found. Elapsed time is {elapsed_time:.2f} seconds.")
        if elapsed_time < CACHE_TIMEOUT:
            print("Cached key remains valid. Returning the cached key.")
            return cached_key
        print("Cached key has expired.")
    else:
        print("No cached key is present.")
    return None


def cache_key(key: bytes) -> None:
    global cached_key, cached_timestamp
    cached_key = key
    cached_timestamp = time.time()
    print(f"New key has been cached at timestamp: {cached_timestamp}")


def check_filesystem(directory: str) -> bool:
    supported_filesystems = ["ext4", "xfs", "btrfs"]
    try:
        result = subprocess.run(["df", "-T", directory], capture_output=True, text=True, check=True)
        output = result.stdout.strip()
        print(f"The output of the 'df -T' command is as follows:\n{output}")

        lines = output.split("\n")
        if len(lines) < 2:
            print("Unable to parse the output of 'df -T' for filesystem type.")
            return False

        data_line = lines[1].split()
        print(f"Filesystem details parsed from the output: {data_line}")
        if len(data_line) < 2:
            print("Insufficient data found in the output to determine the filesystem type.")
            return False

        fs_type = data_line[1].lower()
        print(f"Detected filesystem type is {fs_type}")

        if fs_type in supported_filesystems:
            print(f"Filesystem check passed. The directory '{directory}' is on a supported filesystem ({fs_type}).")
            return True

        print(f"Filesystem check failed. The directory '{directory}' is on an unsupported filesystem ({fs_type}).")
        return False
    except Exception as e:
        print(f"An error occurred while checking the filesystem for '{directory}'. Error details: {e}")
        return False


def secure_delete(file_path: str) -> None:
    print(f"Initiating secure deletion of {file_path}.")
    try:
        subprocess.run(["shred", "--remove", file_path], check=True)
        print(f"File {file_path} has been securely deleted using shred.")
    except Exception as e:
        print(f"The shred command encountered an error for {file_path}: {e}")
        try:
            os.remove(file_path)
            print(f"File {file_path} has been deleted using standard deletion, as shred was not available.")
        except Exception as e2:
            print(f"An error occurred while deleting {file_path}: {e2}")


def destroy_file(file_path: str) -> None:
    print("DESTROY command engaged...")

    if os.path.exists(config_file):
        config = load_configuration()
        shadow_folder = os.path.abspath(config.get("encrypted_directory", ""))
        target_path = os.path.abspath(file_path)
        print(f"Shadow folder is located at: {shadow_folder}")
        print(f"Target file path is: {target_path}")
        if target_path.startswith(shadow_folder):
            print("Error. It is not permitted to destroy files within the shadow folder.")
            return

    if not os.path.exists(file_path):
        print(f"The file {file_path} was not found.")
        return

    if is_linux_system():
        try:
            subprocess.run(["chattr", "-i", file_path], check=True)
            print(f"The immutable flag has been removed from {file_path}.")
        except Exception as e:
            print(f"An error occurred while removing the immutable flag from {file_path}: {e}")

    secure_delete(file_path)

    config = load_configuration()
    master_key = bytes.fromhex(config["file_enc_key"])
    append_log_entry(log_file, master_key, "Command", f"Destroyed file {file_path}")


def is_strong_passphrase(passphrase: str) -> bool:
    length_ok = len(passphrase) >= 8
    has_letter = any(c.isalpha() for c in passphrase)
    has_digit = any(c.isdigit() for c in passphrase)
    strong = length_ok and has_letter and has_digit
    print(
        "Passphrase strength check: "
        f"length_ok={length_ok}, has_letter={has_letter}, has_digit={has_digit}, strong={strong}"
    )
    return strong


def prompt_for_new_passphrase() -> bytes:
    while True:
        pass1 = getpass("Enter a strong config encryption passphrase (min 8 chars, letters & digits): ")
        pass2 = getpass("Confirm the passphrase: ")

        if pass1 != pass2:
            print("Passphrases do not match. Please try again.")
            continue

        print("Passphrase entries match.")

        if not is_strong_passphrase(pass1):
            print("Weak passphrase. It must be at least 8 characters and include letters and digits.")
            continue

        print("Passphrase meets strength requirements.")

        salt = get_config_salt()
        print(f"Retrieved salt: {salt.hex()}")

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend(),
        )
        key = kdf.derive(pass1.encode())
        print(f"Derived key: {key.hex()}")

        cache_key(key)
        print("Key has been cached successfully.")
        return key


def prompt_for_existing_passphrase(encrypted_data: bytes) -> bytes:
    attempts = 0
    while attempts < 3:
        cached = get_cached_key()
        if cached:
            try:
                _ = decrypt_bytes(encrypted_data, cached)
                return cached
            except Exception:
                pass

        p = getpass("Enter config encryption passphrase to decrypt config: ")
        if not is_strong_passphrase(p):
            print("Passphrase does not meet requirements.")
            attempts += 1
            continue

        salt = get_config_salt()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend(),
        )
        try:
            key = kdf.derive(p.encode())
            _ = decrypt_bytes(encrypted_data, key)
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


def get_config_salt() -> bytes:
    if not os.path.exists(salt_file):
        salt = os.urandom(16)
        with open(salt_file, "wb") as f:
            f.write(salt)
    else:
        with open(salt_file, "rb") as f:
            salt = f.read()
    return salt


def generate_encryption_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def encrypt_bytes(data: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext


def decrypt_bytes(enc_data: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = enc_data[:12]
    ciphertext = enc_data[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)


def encrypt_file(src: str, dst: str, key: bytes) -> None:
    with open(src, "rb") as f:
        data = f.read()
    enc_data = encrypt_bytes(data, key)
    with open(dst, "wb") as f:
        f.write(enc_data)


def decrypt_file_contents(path: str, key: bytes) -> bytes:
    with open(path, "rb") as f:
        data = f.read()
    return decrypt_bytes(data, key)


def compute_sha256(data: bytes) -> bytes:
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.digest()


def derive_file_encryption_key(master_key: bytes, filename: str) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=filename.encode(),
        info=b"file encryption",
        backend=default_backend(),
    )
    return hkdf.derive(master_key)


def backup_file_hash(filename: str, enc_hash: bytes) -> None:
    backup = {}

    if os.path.exists(hash_backup_file):
        try:
            config = load_configuration()
            master_key = bytes.fromhex(config["file_enc_key"])
            with open(hash_backup_file, "rb") as f:
                encrypted_backup = f.read()
            decrypted_backup = decrypt_bytes(encrypted_backup, master_key).decode("utf-8")
            backup = json.loads(decrypted_backup)
        except Exception:
            backup = {}

    backup[filename] = base64.b64encode(enc_hash).decode()
    backup_json = json.dumps(backup, indent=4)

    config = load_configuration()
    master_key = bytes.fromhex(config["file_enc_key"])
    encrypted_backup = encrypt_bytes(backup_json.encode(), master_key)
    with open(hash_backup_file, "wb") as f:
        f.write(encrypted_backup)

    print(f"Backup updated for {filename} in encrypted hash_backup.json")


def store_file_hash(enc_filepath: str, file_data: bytes, key: bytes) -> None:
    file_hash = compute_sha256(file_data).hex()
    enc_hash = encrypt_bytes(file_hash.encode(), key)
    try:
        xattr.setxattr(enc_filepath, "user.shadowhash", enc_hash)
        print(f"Stored encrypted hash in xattr for {os.path.basename(enc_filepath)} (SHA-256: {file_hash})")
        backup_file_hash(os.path.basename(enc_filepath), enc_hash)
    except Exception as e:
        print(f"Error setting xattr on {enc_filepath}: {e}")


def verify_file_hash(enc_filepath: str, file_data: bytes, key: bytes) -> bool:
    computed = compute_sha256(file_data).hex()
    try:
        stored = xattr.getxattr(enc_filepath, "user.shadowhash")
        decrypted = decrypt_bytes(stored, key).decode()
        return computed == decrypted
    except Exception as e:
        print(f"Error retrieving/decrypting xattr from {enc_filepath}: {e}")
        return False


def hide_directory(directory: str) -> str:
    abs_path = os.path.abspath(directory)
    base = os.path.basename(abs_path)
    if not base.startswith("."):
        new_path = os.path.join(os.path.dirname(abs_path), "." + base)
        os.rename(abs_path, new_path)
        print(f"Renamed directory to hidden: {new_path}")
        return new_path
    return abs_path


def set_file_read_only(path: str) -> None:
    os.chmod(path, 0o444)
    print(f"Set file to read-only: {os.path.basename(path)}")


def set_directory_read_only(directory: str) -> None:
    os.chmod(directory, 0o555)
    print(f"Set directory to read-only: {os.path.basename(directory)}")


def make_file_writable(path: str) -> None:
    os.chmod(path, 0o644)
    print(f"Made file writable: {os.path.basename(path)}")


def is_linux_system() -> bool:
    return platform.system() == "Linux"


def set_directory_immutable(directory: str) -> None:
    if not is_linux_system():
        print("Immutable flag not supported on this platform.")
        return
    try:
        subprocess.run(["chattr", "-R", "+i", directory], check=True)
        print(f"Immutable flag set on: {directory}")
    except subprocess.CalledProcessError as e:
        print(f"Error setting immutable flag on {directory}: {e}")


def remove_directory_immutable(directory: str) -> None:
    if not is_linux_system():
        print("Immutable flag not supported on this platform; skipping.")
        return
    try:
        subprocess.run(["chattr", "-R", "-i", directory], check=True)
        print(f"Immutable flag removed from: {directory}")
    except subprocess.CalledProcessError as e:
        print(f"Error removing immutable flag from {directory}: {e}")


def get_file_stats(path: str) -> tuple[int, str]:
    stat_info = os.stat(path)
    size = stat_info.st_size
    mtime = datetime.datetime.fromtimestamp(stat_info.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
    return size, mtime


def read_log(log_path: str, master_key: bytes) -> str:
    if not os.path.exists(log_path):
        return ""
    try:
        with open(log_path, "rb") as f:
            encrypted_log = f.read()
        decrypted = decrypt_bytes(encrypted_log, master_key)
        return decrypted.decode("utf-8")
    except Exception:
        return ""


def write_log(log_path: str, master_key: bytes, log_content: str) -> None:
    encrypted_log = encrypt_bytes(log_content.encode("utf-8"), master_key)
    with open(log_path, "wb") as f:
        f.write(encrypted_log)


def append_log_entry(
    log_path: str,
    master_key: bytes,
    entry_type: str,
    message: str,
    file_event: str = None,
    file_name: str = None,
    size: str = None,
    file_format: str = None,
    file_hash: str = None,
) -> None:
    log_content = read_log(log_path, master_key)
    entries = [line for line in log_content.splitlines() if line.lstrip().startswith("Entry")]
    entry_number = len(entries) + 1
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    signature = hmac.new(master_key, f"{timestamp} {message}".encode("utf-8"), hashlib.sha256).hexdigest()

    new_entry = f"Entry {entry_number}: {entry_type}\nTimestamp: {timestamp}\n"
    if entry_type == "Command":
        new_entry += f"Message: {message}\n"
    elif entry_type == "File":
        new_entry += f"Event: {file_event}\n"
        new_entry += f"File Name: {file_name}\n"
        new_entry += f"Size: {size}\n"
        new_entry += f"Format: {file_format}\n"
        new_entry += f"Hash (SHA-256): {file_hash}\n"
    new_entry += f"HMAC: {signature}\n-----\n"

    updated_log = log_content + new_entry
    write_log(log_path, master_key, updated_log)


def display_log_ledger(log_path: str, master_key: bytes) -> None:
    log_content = read_log(log_path, master_key)
    if not log_content:
        print("No log ledger found.")
        return
    print("===== LOG LEDGER =====")
    print(log_content)
    print("======================")


def print_status() -> None:
    config = load_configuration()
    src_dir = config["source_directory"]
    enc_dir = config["encrypted_directory"]

    num_source = len([f for f in os.listdir(src_dir) if os.path.isfile(os.path.join(src_dir, f))])
    num_enc = len([f for f in os.listdir(enc_dir) if f.endswith(".enc")])

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
    print(status)

    config = load_configuration()
    master_key = bytes.fromhex(config["file_enc_key"])
    append_log_entry(log_file, master_key, "Command", "Status command invoked")


def generate_forensic_report() -> None:
    config = load_configuration()
    src_dir = config["source_directory"]
    enc_dir = config["encrypted_directory"]

    num_source = len([f for f in os.listdir(src_dir) if os.path.isfile(os.path.join(src_dir, f))])
    num_enc = len([f for f in os.listdir(enc_dir) if f.endswith(".enc")])

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
        "----- FILE METADATA -----",
    ]

    for fname in os.listdir(src_dir):
        sfile = os.path.join(src_dir, fname)
        if os.path.isfile(sfile):
            size, mtime = get_file_stats(sfile)
            report_lines.append(f"{fname} | {size} bytes | {mtime}")

    report_lines.append("")
    report_lines.append("----- LOG LEDGER -----")

    if os.path.exists(log_file):
        try:
            master_key = bytes.fromhex(config["file_enc_key"])
            log_content = read_log(log_file, master_key)
            report_lines.append(log_content)
        except Exception:
            report_lines.append("Error decrypting log ledger.")
    else:
        report_lines.append("No log ledger found.")

    report_lines.append("=============================")

    report_text = "\n".join(report_lines)
    print(report_text)

    master_key = bytes.fromhex(config["file_enc_key"])
    append_log_entry(log_file, master_key, "Command", "Forensic report generated")


def backup_system(dump_path: str) -> None:
    print("BACKUP command engaged...")
    config = load_configuration()
    enc_dir = config["encrypted_directory"]

    if not os.path.exists(metadata_directory) or not os.path.exists(enc_dir):
        print("Missing metadata or encrypted directory. Cannot create backup.")
        return

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_temp = os.path.join("/tmp", f"shadow_backup_{timestamp}")
    os.makedirs(backup_temp, exist_ok=True)

    meta_dest = os.path.join(backup_temp, os.path.basename(metadata_directory))
    enc_dest = os.path.join(backup_temp, os.path.basename(enc_dir))

    shutil.copytree(metadata_directory, meta_dest)
    shutil.copytree(enc_dir, enc_dest)

    zip_name = f"shadow_backup_{timestamp}.zip"
    zip_path = os.path.join(dump_path, zip_name)

    shutil.make_archive(zip_path.replace(".zip", ""), "zip", root_dir=backup_temp)
    shutil.rmtree(backup_temp)

    print(f"Backup created at {zip_path}")

    master_key = bytes.fromhex(config["file_enc_key"])
    append_log_entry(log_file, master_key, "Command", f"Backup created at {zip_path}")


def restore_system(zipfile: str, source_dir: str, enc_dir: str) -> None:
    print("RESTORE command engaged...")

    if not os.path.isfile(zipfile):
        print("Backup zip file not found.")
        return

    temp_extract = "/tmp/shadow_restore"
    if os.path.exists(temp_extract):
        shutil.rmtree(temp_extract)
    os.makedirs(temp_extract)
    shutil.unpack_archive(zipfile, temp_extract)

    extracted_dirs = os.listdir(temp_extract)
    meta_src = next((os.path.join(temp_extract, d) for d in extracted_dirs if ".shadowmeta" in d), None)
    enc_src = next((os.path.join(temp_extract, d) for d in extracted_dirs if ".shadowmeta" not in d), None)

    if not meta_src or not enc_src:
        print("Backup zip is missing required folders.")
        return

    if os.path.exists(metadata_directory):
        shutil.rmtree(metadata_directory)
    shutil.copytree(meta_src, metadata_directory)
    print(f"Metadata restored to: {metadata_directory}")

    if os.path.exists(enc_dir):
        shutil.rmtree(enc_dir)
    shutil.copytree(enc_src, enc_dir)
    enc_dir = hide_directory(enc_dir)
    print(f"Encrypted folder restored and hidden: {enc_dir}")

    if not os.path.exists(source_dir):
        os.makedirs(source_dir)
        os.chmod(source_dir, 0o777)
        print(f"Created source directory: {source_dir}")

    config = load_configuration()
    config["source_directory"] = os.path.abspath(source_dir)
    config["encrypted_directory"] = os.path.abspath(enc_dir)
    save_configuration(config)

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

    set_directory_read_only(enc_dir)
    set_directory_immutable(enc_dir)

    master_key = bytes.fromhex(config["file_enc_key"])
    append_log_entry(log_file, master_key, "Command", "System restored from backup.")
    print("RESTORE COMPLETED SUCCESSFULLY.")


def remove_system() -> None:
    print("REMOVE command engaged...")

    config = load_configuration() if os.path.exists(config_file) else None
    enc_dir = config["encrypted_directory"] if config and "encrypted_directory" in config else None

    if enc_dir and os.path.exists(enc_dir):
        remove_directory_immutable(enc_dir)
        for root, dirs, files in os.walk(enc_dir, topdown=False):
            for name in files:
                secure_delete(os.path.join(root, name))
            for name in dirs:
                try:
                    os.rmdir(os.path.join(root, name))
                except Exception as e:
                    print(f"Error removing directory {name}: {e}")
        try:
            os.rmdir(enc_dir)
            print(f"Encrypted directory {enc_dir} removed.")
        except Exception as e:
            print(f"Error removing encrypted directory {enc_dir}: {e}")
    else:
        print("Encrypted directory not found.")

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

    config = load_configuration()
    master_key = bytes.fromhex(config["file_enc_key"])
    append_log_entry(log_file, master_key, "Command", "System removed (teardown) executed")


def save_configuration(config_data: dict) -> None:
    config_data["version"] = CONFIG_VERSION
    plaintext = json.dumps(config_data).encode("utf-8")

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
        key = get_cached_key() or prompt_for_new_passphrase()

    encrypted_config = encrypt_bytes(plaintext, key)
    with open(config_file, "wb") as f:
        f.write(encrypted_config)
    print(f"Encrypted configuration saved at: {config_file}")


def load_configuration() -> dict:
    if not os.path.exists(config_file):
        print("Configuration not found. Please run --deploy first.")
        sys.exit(1)

    with open(config_file, "rb") as f:
        encrypted_config = f.read()

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
        key = prompt_for_existing_passphrase(encrypted_config)

    try:
        plaintext = decrypt_bytes(encrypted_config, key)
    except Exception as e:
        print(f"Error decrypting configuration file: {e}")
        sys.exit(1)

    config_data = json.loads(plaintext.decode("utf-8"))
    print("Configuration loaded successfully.")
    return config_data


def deploy_system(source_dir: str, encrypted_dir: str) -> None:
    print("DEPLOY command engaged...")

    abs_source = os.path.abspath(source_dir)
    abs_encrypted = os.path.abspath(encrypted_dir)

    if not os.path.exists(abs_source):
        os.makedirs(abs_source)
        os.chmod(abs_source, 0o777)
        print(f"Created source directory: {abs_source}")
    else:
        print(f"Source directory exists: {abs_source}")

    if not os.path.exists(abs_encrypted):
        os.makedirs(abs_encrypted)
        print(f"Created encrypted directory: {abs_encrypted}")
    else:
        print(f"Encrypted directory exists: {abs_encrypted}")

    abs_encrypted = hide_directory(abs_encrypted)

    if not is_linux_system():
        print("Error: This script requires Linux.")
        sys.exit(1)

    if not check_filesystem(abs_encrypted):
        print("Deployment aborted due to unsupported filesystem.")
        sys.exit(1)

    if not os.path.exists(metadata_directory):
        os.makedirs(metadata_directory)
        print(f"Created metadata directory: {metadata_directory}")
    else:
        print(f"Metadata directory exists: {metadata_directory}")

    for path in [log_file, hash_backup_file]:
        with open(path, "w") as f:
            f.write("")
    print("Initialized log ledger and hash backup file.")

    file_enc_key = generate_encryption_key()
    file_enc_key_hex = file_enc_key.hex()
    _ = prompt_for_new_passphrase()

    config_data = {
        "source_directory": abs_source,
        "encrypted_directory": abs_encrypted,
        "deployment_time": datetime.datetime.now().isoformat(),
        "file_enc_key": file_enc_key_hex,
    }
    save_configuration(config_data)

    items = os.listdir(abs_source)
    if not items:
        print("No files found in source directory.")
    else:
        print(f"Found {len(items)} item(s) in source directory.")

    config = load_configuration()
    master_key = bytes.fromhex(config["file_enc_key"])
    append_log_entry(log_file, master_key, "Command", "Deploy command invoked.")

    for item in items:
        src_file = os.path.join(abs_source, item)
        if os.path.isfile(src_file):
            print(f"Processing file: {item}")
            enc_file = os.path.join(abs_encrypted, item + ".enc")
            with open(src_file, "rb") as f:
                data = f.read()
            per_file_key = derive_file_encryption_key(file_enc_key, item)
            file_hash = compute_sha256(data).hex()
            print(f"Encrypting {item} with hash (SHA-256: {file_hash})")
            encrypt_file(src_file, enc_file, per_file_key)
            set_file_read_only(enc_file)
            store_file_hash(enc_file, data, per_file_key)
            size_bytes, _ = get_file_stats(src_file)
            append_log_entry(
                log_file,
                master_key,
                "File",
                "",
                file_event="File Added",
                file_name=item,
                size=f"{size_bytes} bytes",
                file_format=os.path.splitext(item)[1],
                file_hash=file_hash,
            )

    set_directory_read_only(abs_encrypted)
    set_directory_immutable(abs_encrypted)
    append_log_entry(log_file, master_key, "Command", "Deployment completed and encrypted directory secured.")
    print("DEPLOYMENT SUCCESSFUL.")


def update_system(auto_mode: bool = False) -> None:
    print("UPDATE/REVIEW command engaged...")

    config = load_configuration()
    src_dir = config["source_directory"]
    enc_dir = config["encrypted_directory"]

    file_enc_key = bytes.fromhex(config["file_enc_key"])
    master_key = file_enc_key
    append_log_entry(log_file, master_key, "Command", "Update command invoked")

    remove_directory_immutable(enc_dir)
    os.chmod(enc_dir, 0o755)
    append_log_entry(log_file, master_key, "Command", "Removed immutable flag for update")

    src_files = {f for f in os.listdir(src_dir) if os.path.isfile(os.path.join(src_dir, f))}
    enc_files = {f[:-4] for f in os.listdir(enc_dir) if f.endswith(".enc")}

    new_files = src_files - enc_files
    deleted_files = enc_files - src_files
    modified_files = set()

    for f in src_files & enc_files:
        src_file = os.path.join(src_dir, f)
        enc_file = os.path.join(enc_dir, f + ".enc")
        with open(src_file, "rb") as sf:
            src_data = sf.read()
        per_file_key = derive_file_encryption_key(file_enc_key, f)
        try:
            enc_data = decrypt_file_contents(enc_file, per_file_key)
        except Exception as e:
            print(f"Error decrypting {enc_file}: {e}")
            enc_data = None
        if enc_data is None or src_data != enc_data:
            modified_files.add(f)

    print(f"\nNew files detected: {new_files}")
    print(f"Modified files detected: {modified_files}")
    print(f"Deleted files detected: {deleted_files}")

    for f in sorted(new_files):
        src_file = os.path.join(src_dir, f)
        print(f"\nNew file detected: {f}")
        size_bytes, mtime = get_file_stats(src_file)
        print(f"Metadata: {f} | {size_bytes} bytes | {mtime}")
        choice = "y" if auto_mode else input("Add this file? (y/n): ").strip().lower()
        if choice == "y":
            enc_file = os.path.join(enc_dir, f + ".enc")
            with open(src_file, "rb") as sf:
                data = sf.read()
            per_file_key = derive_file_encryption_key(file_enc_key, f)
            file_hash = compute_sha256(data).hex()
            print(f"Encrypting {f} with new hash (SHA-256: {file_hash})")
            encrypt_file(src_file, enc_file, per_file_key)
            set_file_read_only(enc_file)
            store_file_hash(enc_file, data, per_file_key)
            append_log_entry(
                log_file,
                master_key,
                "File",
                "",
                file_event="File Added",
                file_name=f,
                size=f"{size_bytes} bytes",
                file_format=os.path.splitext(f)[1],
                file_hash=file_hash,
            )
        else:
            append_log_entry(log_file, master_key, "Command", f"Skipped adding file {f}")

    for f in sorted(modified_files):
        src_file = os.path.join(src_dir, f)
        enc_file = os.path.join(enc_dir, f + ".enc")
        print(f"\nModified file detected: {f}")
        size_bytes, mtime = get_file_stats(src_file)
        print(f"Source metadata: {f} | {size_bytes} bytes | {mtime}")
        if os.path.exists(enc_file):
            enc_size, enc_mtime = get_file_stats(enc_file)
            print(f"Encrypted metadata: {f}.enc | {enc_size} bytes | {enc_mtime}")
        choice = "y" if auto_mode else input("Update this file? (y/n): ").strip().lower()
        if choice == "y":
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
                log_file,
                master_key,
                "File",
                "",
                file_event="File Modified",
                file_name=f,
                size="(old) > (new)",
                file_format="(old) > (new)",
                file_hash="(old) > " + file_hash,
            )
        else:
            append_log_entry(log_file, master_key, "Command", f"Skipped updating file {f}")

    for f in sorted(deleted_files):
        enc_file = os.path.join(enc_dir, f + ".enc")
        print(f"\nDeletion detected: Source file '{f}' is missing.")
        choice = "y" if auto_mode else input("Remove encrypted file? (y/n): ").strip().lower()
        if choice == "y":
            make_file_writable(enc_file)
            try:
                os.remove(enc_file)
                print(f"Encrypted file '{enc_file}' removed.")
                append_log_entry(
                    log_file,
                    master_key,
                    "File",
                    "",
                    file_event="File Removed",
                    file_name=f,
                    size="N/A",
                    file_format="N/A",
                    file_hash="N/A",
                )
            except OSError as e:
                print(f"Error removing encrypted file '{enc_file}': {e}")
        else:
            append_log_entry(log_file, master_key, "Command", f"Kept encrypted file for deleted source file '{f}'")

    for f in os.listdir(enc_dir):
        if f.endswith(".enc"):
            set_file_read_only(os.path.join(enc_dir, f))

    set_directory_read_only(enc_dir)
    set_directory_immutable(enc_dir)
    append_log_entry(log_file, master_key, "Command", "Update applied and encrypted directory secured.")
    print("UPDATE/REVIEW COMPLETED SUCCESSFULLY.")


def dump_single_file(file_name: str, dump_path: str) -> None:
    print("DUMP command engaged...")
    config = load_configuration()
    enc_dir = config["encrypted_directory"]
    file_enc_key = bytes.fromhex(config["file_enc_key"])
    master_key = file_enc_key

    append_log_entry(log_file, master_key, "Command", f"Dump command invoked for {file_name}")

    enc_file = os.path.join(enc_dir, file_name + ".enc")
    if not os.path.exists(enc_file):
        print(f"Encrypted file for {file_name} not found.")
        return

    per_file_key = derive_file_encryption_key(file_enc_key, file_name)
    try:
        data = decrypt_file_contents(enc_file, per_file_key)
    except Exception as e:
        print(f"Error decrypting {file_name}: {e}")
        return

    if not os.path.exists(dump_path):
        os.makedirs(dump_path)
        print(f"Created dump directory: {dump_path}")

    dest = os.path.join(dump_path, file_name)
    with open(dest, "wb") as f:
        f.write(data)

    os.chmod(dest, 0o777)
    set_file_read_only(dest)
    print(f"Dumped decrypted file to {dest}")


def clone_all_files(dump_path: str) -> None:
    print("CLONE command engaged...")
    config = load_configuration()
    enc_dir = config["encrypted_directory"]
    file_enc_key = bytes.fromhex(config["file_enc_key"])
    master_key = file_enc_key

    append_log_entry(log_file, master_key, "Command", "Clone command invoked")

    if not os.path.exists(dump_path):
        os.makedirs(dump_path)
        print(f"Created dump directory: {dump_path}")

    for enc in os.listdir(enc_dir):
        if enc.endswith(".enc"):
            fname = enc[:-4]
            per_file_key = derive_file_encryption_key(file_enc_key, fname)
            try:
                data = decrypt_file_contents(os.path.join(enc_dir, enc), per_file_key)
            except Exception as e:
                print(f"Error decrypting {fname}: {e}")
                continue

            dest = os.path.join(dump_path, fname)
            with open(dest, "wb") as f:
                f.write(data)

            os.chmod(dest, 0o777)
            set_file_read_only(dest)

    print(f"Cloned all decrypted files to {dump_path}")


def verify_single_file(file_name: str) -> None:
    print("VERIFY command engaged...")

    config = load_configuration()
    src_dir = config["source_directory"]
    enc_dir = config["encrypted_directory"]

    file_enc_key = bytes.fromhex(config["file_enc_key"])
    master_key = file_enc_key

    append_log_entry(log_file, master_key, "Command", f"Verify command invoked for {file_name}")

    src_file = os.path.join(src_dir, file_name)
    enc_file = os.path.join(enc_dir, file_name + ".enc")

    if not os.path.exists(src_file):
        print(f"Source file {file_name} does not exist.")
        return

    if not os.path.exists(enc_file):
        print(f"Encrypted file for {file_name} does not exist.")
        return

    with open(src_file, "rb") as f:
        src_data = f.read()

    per_file_key = derive_file_encryption_key(file_enc_key, file_name)

    try:
        enc_data = decrypt_file_contents(enc_file, per_file_key)
    except Exception as e:
        print(f"Error decrypting {file_name}: {e}")
        return

    src_hash = hashlib.sha256(src_data).hexdigest()
    enc_hash = hashlib.sha256(enc_data).hexdigest()
    size_bytes, mtime = get_file_stats(src_file)

    print(f"\n{file_name} | {size_bytes} bytes | {mtime}")
    print(f"Source Hash (SHA-256): {src_hash}")
    print(f"Shadow Hash (SHA-256): {enc_hash}")

    if src_hash == enc_hash:
        print("Outcome     : Hashes match")
    else:
        print("Outcome     : Hashes do NOT match")


def audit_all_files() -> None:
    print("AUDIT command engaged...")

    config = load_configuration()
    src_dir = config["source_directory"]
    enc_dir = config["encrypted_directory"]

    file_enc_key = bytes.fromhex(config["file_enc_key"])
    master_key = file_enc_key

    append_log_entry(log_file, master_key, "Command", "Audit command invoked")

    print("\n===== AUDIT REPORT =====")

    for fname in sorted(os.listdir(src_dir)):
        src_file = os.path.join(src_dir, fname)
        enc_file = os.path.join(enc_dir, fname + ".enc")

        if os.path.isfile(src_file) and os.path.exists(enc_file):
            with open(src_file, "rb") as f:
                src_data = f.read()

            per_file_key = derive_file_encryption_key(file_enc_key, fname)

            try:
                enc_data = decrypt_file_contents(enc_file, per_file_key)
            except Exception as e:
                print(f"{fname}: Error decrypting: {e}")
                continue

            src_hash = hashlib.sha256(src_data).hexdigest()
            enc_hash = hashlib.sha256(enc_data).hexdigest()
            size_bytes, mtime = get_file_stats(src_file)

            print(f"{fname} | {size_bytes} bytes | {mtime}")
            print(f"Source Hash (SHA-256): {src_hash}")
            print(f"Shadow Hash (SHA-256): {enc_hash}")

            if src_hash == enc_hash:
                print("Outcome     : Hashes match\n")
            else:
                print("Outcome     : Hashes do NOT match\n")

    print("========================")
    append_log_entry(log_file, master_key, "Command", "Audit completed")


def show_metadata(file_name: str) -> None:
    print("META command engaged...")

    config = load_configuration()
    enc_dir = config["encrypted_directory"]

    file_enc_key = bytes.fromhex(config["file_enc_key"])
    master_key = file_enc_key

    append_log_entry(log_file, master_key, "Command", f"Meta command invoked for {file_name}")

    enc_file = os.path.join(enc_dir, file_name + ".enc")
    if not os.path.exists(enc_file):
        print(f"Encrypted file for {file_name} not found.")
        return

    size_bytes, mtime = get_file_stats(enc_file)
    per_file_key = derive_file_encryption_key(file_enc_key, file_name)

    try:
        stored_hash = xattr.getxattr(enc_file, "user.shadowhash")
        decrypted_hash = decrypt_bytes(stored_hash, per_file_key).decode()
    except Exception:
        decrypted_hash = "N/A"

    print("\n===== FILE METADATA =====")
    print(f"{file_name}.enc | {size_bytes} bytes | {mtime}")
    print(f"Hash (SHA-256): {decrypted_hash}")
    print("=========================")


def change_passphrase() -> None:
    print("PASS-PHRASE command engaged...")

    config = load_configuration()
    _ = get_cached_key() or prompt_for_existing_passphrase(open(config_file, "rb").read())
    _ = prompt_for_new_passphrase()

    save_configuration(config)

    config = load_configuration()
    master_key = bytes.fromhex(config["file_enc_key"])
    append_log_entry(log_file, master_key, "Command", "Passphrase rotation completed")
    print("Passphrase rotation completed.")


def panic_mode(config_dir: str, shadow_dir: str, dump_dir: str, passphrase: str) -> None:
    print("PANIC command engaged...")

    config_path = os.path.join(config_dir, "config.json")
    if not os.path.exists(config_path):
        print("Error: config.json not found in specified config folder.")
        return

    try:
        with open(config_path, "rb") as f:
            encrypted_config = f.read()
    except Exception as e:
        print(f"Error reading config.json: {e}")
        return

    salt_path = os.path.join(config_dir, "config_salt.bin")
    if not os.path.exists(salt_path):
        print("Error: config_salt.bin not found in specified config folder.")
        return

    try:
        with open(salt_path, "rb") as f:
            salt = f.read()
    except Exception as e:
        print(f"Error reading salt file: {e}")
        return

    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend(),
        )
        key = kdf.derive(passphrase.encode())
        plaintext = decrypt_bytes(encrypted_config, key)
        config = json.loads(plaintext.decode("utf-8"))
        print("Configuration successfully decrypted.")
    except Exception as e:
        print(f"Failed to decrypt config.json: {e}")
        return

    file_enc_key = bytes.fromhex(config["file_enc_key"])
    processed = 0
    failed = 0

    if not os.path.exists(shadow_dir):
        print("Error: Shadow folder path does not exist.")
        return

    if not os.path.exists(dump_dir):
        os.makedirs(dump_dir)
        print(f"Created dump directory: {dump_dir}")

    print("Processing encrypted files...")

    for f in os.listdir(shadow_dir):
        if f.endswith(".enc"):
            enc_path = os.path.join(shadow_dir, f)
            file_name = f[:-4]
            try:
                per_file_key = derive_file_encryption_key(file_enc_key, file_name)
                data = decrypt_file_contents(enc_path, per_file_key)

                dest_path = os.path.join(dump_dir, file_name)
                with open(dest_path, "wb") as out:
                    out.write(data)

                os.chmod(dest_path, 0o777)
                print(f"Decrypted and dumped: {file_name}")
                processed += 1
            except Exception as e:
                print(f"Failed to decrypt {file_name}: {e}")
                failed += 1

    print(f"\nPANIC completed. Files decrypted: {processed}, Failed: {failed}")


def unpack_backup_zip(zip_path: str, dump_path: str) -> None:
    print("UNPACK command engaged...")

    if not os.path.isfile(zip_path):
        print("Provided zip file does not exist.")
        return

    temp_dir = tempfile.mkdtemp(prefix="shadow_unpack_")
    print(f"Extracting backup zip to temporary directory: {temp_dir}")
    try:
        shutil.unpack_archive(zip_path, temp_dir)
    except Exception as e:
        print(f"Failed to extract zip file: {e}")
        return

    meta_path = None
    shadow_path = None

    for root, dirs, _ in os.walk(temp_dir):
        for d in dirs:
            if d == ".shadowmeta":
                meta_path = os.path.join(root, d)
            else:
                try:
                    if any(f.endswith(".enc") for f in os.listdir(os.path.join(root, d))):
                        shadow_path = os.path.join(root, d)
                except Exception:
                    pass

    if not meta_path or not shadow_path:
        print("Failed to locate .shadowmeta or shadow folder in the backup.")
        return

    config_file_path = os.path.join(meta_path, "config.json")
    if not os.path.exists(config_file_path):
        print("Config file not found in the backup.")
        return

    with open(config_file_path, "rb") as f:
        encrypted_config = f.read()

    global salt_file
    original_salt_path = salt_file
    salt_file = os.path.join(meta_path, "config_salt.bin")

    key = prompt_for_existing_passphrase(encrypted_config)
    try:
        decrypted = decrypt_bytes(encrypted_config, key)
        config = json.loads(decrypted.decode())
    except Exception as e:
        print(f"Could not decrypt configuration: {e}")
        salt_file = original_salt_path
        return

    file_enc_key = bytes.fromhex(config["file_enc_key"])
    salt_file = original_salt_path

    if not os.path.exists(dump_path):
        os.makedirs(dump_path)
        print(f"Created dump path: {dump_path}")

    for f in os.listdir(shadow_path):
        if f.endswith(".enc"):
            fname = f[:-4]
            src_path = os.path.join(shadow_path, f)
            try:
                per_file_key = derive_file_encryption_key(file_enc_key, fname)
                data = decrypt_file_contents(src_path, per_file_key)
                dest_path = os.path.join(dump_path, fname)
                with open(dest_path, "wb") as out:
                    out.write(data)
                os.chmod(dest_path, 0o777)
                print(f"Unpacked {fname} to {dest_path}")
            except Exception as e:
                print(f"Failed to decrypt {f}: {e}")

    print("UNPACK COMPLETED SUCCESSFULLY.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "ShadowLock: Secure Offline Storage and Integrity Verification\n\n"
            "Commands:\n"
            "  --deploy <SOURCE_DIRECTORY> <ENCRYPTED_DIRECTORY>\n"
            "  --review\n"
            "  --update\n"
            "  --dump <FILE_NAME> <DUMP_DIRECTORY>\n"
            "  --clone <DUMP_DIRECTORY>\n"
            "  --verify <FILE_NAME>\n"
            "  --audit\n"
            "  --meta <FILE_NAME>\n"
            "  --log\n"
            "  --passphrase\n"
            "  --status\n"
            "  --backup <DUMP_DIRECTORY>\n"
            "  --restore <ZIPFILE> <SOURCE_DIRECTORY> <ENCRYPTED_DIRECTORY>\n"
            "  --report\n"
            "  --remove\n"
            "  --destroy <FILE_PATH>\n"
            "  --panic <CONFIG_DIRECTORY> <SHADOW_DIRECTORY> <DUMP_DIRECTORY> <PASSPHRASE>\n"
            "  --unpack <ZIP_FILE> <DUMP_DIRECTORY>\n"
        )
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--deploy", nargs=2, metavar=("SOURCE_DIRECTORY", "ENCRYPTED_DIRECTORY"))
    group.add_argument("--review", action="store_true")
    group.add_argument("--update", action="store_true")
    group.add_argument("--dump", nargs=2, metavar=("FILE_NAME", "DUMP_DIRECTORY"))
    group.add_argument("--clone", metavar="DUMP_DIRECTORY")
    group.add_argument("--verify", nargs=1, metavar="FILE_NAME")
    group.add_argument("--audit", action="store_true")
    group.add_argument("--meta", metavar="FILE_NAME")
    group.add_argument("--log", action="store_true")
    group.add_argument("--passphrase", action="store_true")
    group.add_argument("--status", action="store_true")
    group.add_argument("--backup", metavar="DUMP_DIRECTORY")
    group.add_argument("--restore", nargs=3, metavar=("ZIPFILE", "SOURCE_DIRECTORY", "ENCRYPTED_DIRECTORY"))
    group.add_argument("--report", action="store_true")
    group.add_argument("--remove", action="store_true")
    group.add_argument("--destroy", metavar="FILE_PATH")
    group.add_argument("--panic", nargs=4, metavar=("CONFIG_DIRECTORY", "SHADOW_DIRECTORY", "DUMP_DIRECTORY", "PASSPHRASE"))
    group.add_argument("--unpack", nargs=2, metavar=("ZIP_FILE", "DUMP_DIRECTORY"))

    args = parser.parse_args()

    if args.deploy:
        deploy_system(args.deploy[0], args.deploy[1])
    elif args.review:
        update_system(auto_mode=False)
    elif args.update:
        update_system(auto_mode=True)
    elif args.dump:
        dump_single_file(args.dump[0], args.dump[1])
    elif args.clone:
        clone_all_files(args.clone)
    elif args.verify:
        verify_single_file(args.verify[0])
    elif args.audit:
        audit_all_files()
    elif args.meta:
        show_metadata(args.meta)
    elif args.log:
        config = load_configuration()
        master_key = bytes.fromhex(config["file_enc_key"])
        display_log_ledger(log_file, master_key)
        append_log_entry(log_file, master_key, "Command", "Displayed log ledger")
    elif args.passphrase:
        change_passphrase()
    elif args.status:
        print_status()
    elif args.backup:
        backup_system(args.backup)
    elif args.restore:
        restore_system(args.restore[0], args.restore[1], args.restore[2])
    elif args.report:
        generate_forensic_report()
    elif args.remove:
        remove_system()
    elif args.destroy:
        destroy_file(args.destroy)
    elif args.panic:
        config_dir, shadow_dir, dump_dir, passphrase = args.panic
        panic_mode(config_dir, shadow_dir, dump_dir, passphrase)
    elif args.unpack:
        zip_path, dump_path = args.unpack
        unpack_backup_zip(zip_path, dump_path)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
