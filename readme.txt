SHADOWLOCK - Forensically Integrated Secure Offline File Storage & Backup Tool
Institution: Middlesex Univeristy
Module: CST3590 - Individual Project
Module Leader: Dr Ian Mitchell
Supervisor: Dr Glenford Mapp
Author: Erwin Magielda


ABOUT
============================================================
Shadowlock is a Linux-based forensic-grade file protection and backup system.
It ensures tamper-evident, securely encrypted storage using AES-GCM encryption,
SHA-256 hashing, extended attributes, Linux immutability, and a fully encrypted log ledger.

Shadowlock is purpose-built for high-integrity archiving, tamper-evident storage, forensic file validation, and most critically: a secure, offline backup system.



REQUIREMENTS
============================================================
- Linux only. Lubuntu on Ext4 is strongly recommended.
- Use inside a Virtual Machine for safety.
- Run all commands using sudo python3.
- Use full absolute paths in every command.
- Configuration folder is stored in /root/.shadowmeta
- All commands should be run from the script location.
- Test only with plain text (.txt) files for now.
- Replace /user/ path section with actual username.



INSTALLATION
============================================================
> sudo apt update
> sudo apt install python3 python3-pip -y
> pip3 install cryptography xattr



HELP
============================================================
To view all available commands:
> sudo python3 shadowlock.py --help

--deploy
This command initializes Shadowlock by setting up the system. It processes all files present in the sourcefolder by encrypting them, storing each file's derived hash into extended attributes, and generating the encrypted configuration and log files. The encrypted files are placed in one specified encrypted, immutable, and hidden shadowfolder.

--review
Runs Shadowlock in interactive mode. In this mode, the tool scans for changes in the sourcefolder compared to the encrypted mirror and prompts you to approve each detected sourcefile update, addition, or deletion manually.

--update
Executes an automatic update of the system. It performs the same scan as --review but automatically applies all changes without prompting. New sourcefiles are encrypted and added, modified files are updated, and deleted sourcefiles are removed from the shadowfolder.

--dump
This command decrypts a single specified shadowfile from the shadowfolder and dumps it (writes the decrypted output) to the designated dump directory. 

--clone
Clones all shadowfiles by decrypting them and dumping the plaintext versions into the specified directory. This provides a complete decrypted backup for validation or offline analysis.

--verify
Verifies the integrity of a specified file by computing its SHA-256 hash from the sourcefile and comparing it with the decrypted, stored hash in the encrypted shadowfile's extended attributes. It prints the results, stating whether the hashes match.

--audit
Performs a comprehensive audit by comparing every file in the sourcefolder against its encrypted counterpart in the shadowfolder. The command prints a detailed report showing file sizes, timestamps, computed hashes, and whether each file's integrity is intact.

--meta
Displays metadata for the specified encrypted shadowfile. This includes the file's size, last modification time, and the stored SHA-256 hash that was saved as an extended attribute, helping to verify file integrity without full decryption.

--log
Decrypts and displays the system's log ledger on the console. This log records all command events and file activities in a tamper-evident manner using HMAC signatures, making it useful for forensic auditing.

--passphrase
Rotates the configuration encryption passphrase. Shadowlock will prompt user to enter and confirm a new strong passphrase, update the master encryption key, and then re-encrypt the configuration file with the new key.

--status
Prints a summary of the current system status, including the paths of the sourcefolder and shadowfolder, the count of files in each folder, the deployment time, and the current version of the configuration.

--backup
Creates a zip archive that backs up both the shadowfolder and configfolder (including configuration, salt, logs, and hash backup). The backup archive is stored in the specified dump directory. This archive can later be used for restoration of the system or offline analysis.

--restore
Restores the system from a backup zip archive. It extracts the configuration and encrypted files, updates the source and encrypted directories with the recovered data, and reprocesses the files to ensure the encrypted mirror remains consistent.

--report
Generates and displays a forensic report covering the deployment details, system status, and metadata for every file. This report includes file counts, hashes, timestamps, and the log ledger, offering a comprehensive view of Shadowlock system integrity.

--remove
Securely deletes the entire Shadowlock system: shadowfolder and configfolder. The command removes all files, subdirectories, and logs in a secure manner (using secure deletion methods) to ensure no traces remain.

--destroy
Securely shreds the specified file. The command first attempts to use the shred utility to remove the file securely. If shredding fails, it falls back to standard deletion. Note that files within the shadowfolder cannot be destroyed with this command.

--panic
Enters emergency recovery mode, bypassing the source folder. This command loads the encrypted configuration (using the provided passphrase) from the specified config directory, then uses the recovered file encryption key to decrypt all shadowfiles found in the designated shadow directory. The decrypted files are dumped to the specified dump directory, enabling recovery in critical situations.

--unpack
Extracts and decrypts files from a backup zip archive. The command looks for the backup’s embedded configuration and salt (typically found in a .shadowmeta folder inside the archive), then uses the recovered file encryption key to decrypt every file in the archive's shadow folder. The decrypted files are then written to the designated dump directory.



WORKFLOW
============================================================
--- Step 1: Create main directory to place the script.
> mkdir /home/user/shadowlock/
[NOTE] All commands are run from the above directory with the script present.
> cd /home/user/shadowlock/


--- Step 2: Create sourcefolder for the script to mirror files from.
> mkdir /home/user/shadowlock/source
[NOTE] Directories are created automatically if not present.


--- Step 3: Create some test text files in sourcefolder to mirror into shadowfolder.
> cd ./source/
> echo "test" > f1.txt
> echo "test" > f2.txt
> echo "test" > f3.txt
> cd ..


--- Step 4: Deploy the script.
[SYNTAX] sudo python3 shadowlock.py --deploy <sourcefolder_path> <shadowfolder_path>
> sudo python3 shadowlock.py --deploy /home/user/shadowlock/source/ /home/user/shadowlock/shadow/

[NOTE] The user is prompted to provide currently logged account password.
> ???

[NOTE] The user is prompted to create a strong passphrase and confirm it.
> Password123!
> Password123!

[NOTE] Initiating the shadowlock system with --deploy updates files present in the source folder automatically.
[NOTE] Deploy won't run if an active shadowlock system exists.

[OPTIONAL] Inspect the encrypted shadowfolder contents.
> ls -la ./.shadow/

[OPTIONAL] Inspect the encrypted configfolder contents.
> sudo ls -la /root/.shadowmeta/


--- Step 5: Dump single file to any location.
[SYNTAX] sudo python3 shadowlock.py --dump <shadowfile> <dump_path>
> sudo python3 shadowlock.py --dump f1.txt /home/user/shadowlock/

[NOTE] The user is prompted to confirm existing passphrase.
> Password123!

[OPTIONAL] Display file contents.
> cat f1.txt


--- Step 6: Securely remove any file.
[SYNTAX] sudo python3 shadowlock.py --destroy <file_path>
> sudo python3 shadowlock.py --destroy /home/user/shadowlock/f1.txt

[NOTE] The user is prompted to confirm existing passphrase.
> Password123!

[OPTIONAL] Verify if removal was successful.
> ls -la


--- Step 7: Clone all files to another folder, decrypted.
[SYNTAX] sudo python3 shadowlock.py --clone <dump_path>
> sudo python3 shadowlock.py --clone /home/user/shadowlock/cloned/

[NOTE] The user is prompted to confirm existing passphrase.
> Password123!

[OPTIONAL] Verify if files were dumped successfully.
> ls -la /home/user/shadowlock/clone/

[OPTIONAL] Display cloned file contents.
> cat ./cloned/f1.txt


--- Step 8: Simulate further changes in source folder.
> cd ./source/
> rm f1.txt
> echo "test-test" > f2.txt
> echo "test" > f4.txt
> cd ..


--- Step 9: Run audit to verify hashes against respective files stored in both folders.
[SYNTAX] sudo python3 shadowlock.py --audit
> sudo python3 shadowlock.py --audit

[NOTE] The user is prompted to confirm existing passphrase.
> Password123!


--- Step 10: Manually approve updates to reflect in the shadowfolder.
[SYNTAX] sudo python3 shadowlock.py --review

[NOTE] The user is prompted to confirm existing passphrase.
> Password123!

[NOTE] User is prompted to decide on changes.
> y
> y
> y

[OPTIONAL] Verify if files were reflected in the shadowfolder.
> ls -la ./.shadow/


--- Step 11: Change encryption passphrase
[SYNTAX] sudo python3 shadowlock.py --passphrase
> sudo python3 shadowlock.py --passphrase

[NOTE] The user is prompted to confirm existing passphrase.
> Password123!

[NOTE] The user is prompted to create new strong passphrase and verify it.
> Password321?
> Password321?


--- Step 12: Display system status
[SYNTAX] sudo python3 shadowlock.py --status
> sudo python3 shadowlock.py --status

[NOTE] The user is prompted to confirm existing passphrase.
> Password321?


--- Step 13: Create a backup archive
[SYNTAX] sudo python3 shadowlock.py --backup <dump_path>
> sudo python3 shadowlock.py --backup /home/user/shadowlock/

[NOTE] The user is prompted to confirm existing passphrase.
> Password321?

[NOTE] Backup archive file contains shadowfolder and configfolder contents, allowing restoration or extracting.
[NOTE] Both backup methods require passphrase and certain configfolder files to decrypt shadowfiles contents.


--- Step 14: Securely remove shadowlock system
[SYNTAX] sudo python3 shadowlock.py --remove
> sudo python3 shadowlock.py --remove

[NOTE] The user is prompted to confirm existing passphrase.
> Password321?


--- Step 15: Unpack a backup archive to access files
[SYNTAX] sudo python3 shadowlock.py --unpack <backuparchive_path> <dump_path>
> sudo python3 shadowlock.py --unpack /home/user/shadowlock/shadow_backup_20010101_111100.zip /home/user/shadowlock/unpacked/

[NOTE] The user is prompted to confirm existing passphrase.
> Password321?

[OPTIONAL] Verify if files were unpacked successfully.
> ls -la /home/user/shadowlock/unpacked/

[OPTIONAL] Display unpackd file contents.
> cat ./unpacked/f2.txt


--- Step 16: Fully restore the system from a backup archive
[SYNTAX] sudo python3 shadowlock.py --restore <backuparchive_path> <sourefolder_path> <shadowfolder_path>
> sudo python3 shadowlock.py --restore /home/user/backup/shadow_backup_20010101_111100.zip /home/user/shadowlock/source/ /home/user/shadowlock/shadow/

[NOTE] The user is prompted to confirm the most recent passphrase.
> Password321?

[NOTE] Similarly to --deploy, --restore can be run only if no active shadowlock system is present.


--- Step 17: Run log to verify shadowlock system history ledger.
[SYNTAX] sudo python3 shadowlock.py --log
> sudo python3 shadowlock.py --log

[NOTE] The user is prompted to confirm the most recent passphrase.
> Password321?


--- Step 18: Emergency mode shadowfiles recovery.
[SYNTAX] sudo python3 shadowlock.py --panic <configfolder_path> <shadowfolder_path> <dump_path> <passphrase>
sudo python3 shadowlock.py --panic /root/.shadowmeta/ /home/user/shadowlock/.shadow/ /home/user/shadowlock/emergency/ Password321!

[NOTE] The configfolder location is /root/.shadowmeta/ by default.
[NOTE] The --panic command restores shadowfiles independently from previously created backuparchive.


--- Step 19: Generate a forensic report
[SYNTAX] sudo python3 shadowlock.py --report
> sudo python3 shadowlock.py --report

[NOTE] The user is prompted to confirm the most recent passphrase.
> Password321?


--- Step 20: Final secure teardown
[SYNTAX] sudo python3 shadowlock.py --remove
> sudo python3 shadowlock.py --remove

[NOTE] The user is prompted to confirm the most recent passphrase.
> Password321?
