# ShadowLock

Secure offline file encryption and integrity verification system for controlled environments.

## What It Is
ShadowLock is a local security tool designed to protect sensitive files through strong encryption, integrity verification, and tamper-evident forensic logging. It operates entirely offline and is intended for scenarios where data confidentiality and auditability matter more than convenience.

## Why It Exists
Many encryption tools focus on confidentiality but provide limited visibility into file history, integrity, or forensic state.  
ShadowLock was built to explore how encryption, integrity checking, and audit logging can be combined into a single, operator-controlled system without relying on external services.

## System Overview
ShadowLock follows a deterministic workflow:

1. Deployment of source and encrypted directories  
2. Per-file encryption using derived keys  
3. Integrity verification using encrypted SHA-256 hashes  
4. Tamper-evident forensic logging with HMAC chaining  
5. Controlled recovery, audit, and emergency access modes  

## Project Structure
```
shadowlock/
├── shadowlock.py
├── README.md
└── .gitignore
```

## Usage
Deploy the system by defining a source directory and an encrypted directory:

```bash
python shadowlock.py --deploy <SOURCE_DIRECTORY> <ENCRYPTED_DIRECTORY>
```

Once deployed, ShadowLock supports operations such as:
- Reviewing and synchronising file changes
- Verifying file integrity
- Auditing all protected files
- Dumping or cloning decrypted files
- Creating and restoring encrypted backups
- Generating forensic reports
- Emergency recovery using panic mode

Run the built-in help menu for full command details:

```bash
python shadowlock.py --help
```

## Integrity Model
Each protected file is:
- Encrypted using AES-GCM
- Assigned a unique per-file key derived via HKDF
- Has its SHA-256 hash encrypted and stored as metadata
- Verified during audits, updates, and recovery operations

## Forensic Logging
ShadowLock maintains an encrypted, append-only log ledger that records:
- File creation, modification, and removal events
- Administrative commands and system actions
- Cryptographic HMAC signatures for tamper detection

This design supports post-incident review and forensic analysis.

## Security Notes
ShadowLock is designed for Linux systems and relies on:
- Extended file attributes
- Immutable filesystem flags
- Local key management

It is intended for controlled environments and research use. It has not been hardened or audited for production deployment.

## Status
Prototype / research project.

## Licence
MIT
