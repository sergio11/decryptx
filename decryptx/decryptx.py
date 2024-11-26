from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import bcrypt
from passlib.hash import scrypt, argon2
from tqdm import tqdm
import pyzipper
import os
import gzip
from decryptx.utils.logger import decryptXLogger
from decryptx import __version__

class DecryptX:

    DEFAULT_WORDLIST = '/usr/share/wordlists/rockyou.txt'

    def __init__(self, wordlist_path=None):
        """
        Initialize the HashCracker class with supported hash types.
        
        Args:
            wordlist_path (str): Path to a custom wordlist. Defaults to DEFAULT_WORDLIST if not provided.
        """
        self.wordlist_path = wordlist_path or self.DEFAULT_WORDLIST
        self.supported_hashes = {
            'blake2b': hashlib.blake2b,
            'blake2s': hashlib.blake2s,
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha224': hashlib.sha224,
            'sha256': hashlib.sha256,
            'sha384': hashlib.sha384,
            'sha3_256': hashlib.sha3_256,
            'sha3_384': hashlib.sha3_384,
            'sha3_512': hashlib.sha3_512,
            'sha512': hashlib.sha512,
            'bcrypt': self._verify_bcrypt,
            'scrypt': scrypt.verify,
            'argon2': argon2.verify
        }
        decryptXLogger.info("🚀 HashCracker initialized. Ready to crack some hashes!")

    def _ensure_wordlist_ready(self):
        """Ensure the wordlist is ready and decompressed."""
        wordlist_path = self.wordlist_path
        compressed_path = f"{wordlist_path}.gz"

        if not os.path.exists(wordlist_path):
            if os.path.exists(compressed_path):
                decryptXLogger.info(f"📦 Decompressing {compressed_path}...")
                with gzip.open(compressed_path, 'rb') as gz_file:
                    with open(wordlist_path, 'wb') as out_file:
                        out_file.write(gz_file.read())
                decryptXLogger.info(f"✅ {compressed_path} decompressed to {wordlist_path}.")
            else:
                decryptXLogger.error(f"🚫 Wordlist not found: {wordlist_path} or {compressed_path}")
                raise FileNotFoundError(f"Wordlist not found: {wordlist_path} or {compressed_path}")
        return wordlist_path
    
    def _count_total_lines(self, wordlist_path):
        """Count total lines in the wordlist for progress tracking."""
        try:
            decryptXLogger.info(f"📜 Counting lines in wordlist: {wordlist_path}")
            with open(wordlist_path, 'r', encoding='latin-1') as f:
                line_count = sum(1 for _ in f)
            decryptXLogger.info(f"✅ Total lines in wordlist: {line_count} passwords found.")
            return line_count
        except FileNotFoundError:
            decryptXLogger.error(f"❌ Wordlist file not found: {wordlist_path}")
            raise
        except Exception as ex:
            decryptXLogger.error(f"❌ An error occurred while counting lines: {ex}")
            raise

    def _process_lines(self, lines, hash_value, hash_type, show_progress=False):
        """Process the lines (sequentially or in chunks) to find the matching password."""
        iterable = tqdm(lines, desc="Cracking") if show_progress else lines
        for password in iterable:
            try:
                password = password.strip()
                if hash_type in ['bcrypt', 'scrypt', 'argon2']:
                    if self.supported_hashes[hash_type](password, hash_value):
                        return password
                else:
                    hash_function = self.supported_hashes[hash_type]
                    if hash_function(password.encode()).hexdigest() == hash_value:
                        return password

            except Exception as ex:
                decryptXLogger.debug(f"⚠️ Error processing password '{password}': {ex}")
        return None
    
    def _verify_bcrypt(self, password, hash_value):
        """
        Verify a bcrypt password against a hash.

        Args:
            password (str): The plaintext password.
            hash_value (str): The bcrypt hash.

        Returns:
            bool: True if the password matches, otherwise False.
        """
        try:
            password_bytes = password.encode('latin-1')
            hash_bytes = hash_value.encode('latin-1')
            # Use bcrypt's checkpw function to verify the password against the hash
            if bcrypt.checkpw(password_bytes, hash_bytes):
                decryptXLogger.info(f"🎉 Password matched: {password}")
                return True
            else:
                return False
        except Exception as ex:
            decryptXLogger.error(f"❌ Error verifying bcrypt password: {password}. Exception: {ex}")
            return False

    def crack_hash(self, hash_value, hash_type, max_workers=4, chunk_size=None):
        """
        Attempt to crack a hash using the default password list with concurrency.

        Args:
            hash_value (str): The hash to crack.
            hash_type (str): The type of hash to use.
            max_workers (int): Number of threads to use for parallel processing.
            chunk_size (int, optional): Number of passwords per thread chunk. If None, processes sequentially.

        Returns:
            str: The password that matches the hash if found, otherwise None.
        """
        if hash_type not in self.supported_hashes:
            decryptXLogger.error(f"💀 Invalid hash type: {hash_type}. Supported types are: {list(self.supported_hashes)}")
            raise ValueError(f"Invalid hash type: {hash_type}. Supported types are: {list(self.supported_hashes)}")
        
        wordlist_path = self._ensure_wordlist_ready()
        total_lines = self._count_total_lines(wordlist_path)

        decryptXLogger.info(f"🔍 Attempting to crack hash '{hash_value}' using '{hash_type}' with {total_lines} passwords.")
        
        with open(wordlist_path, 'r', encoding='latin-1') as file:
            lines = file.readlines()

        result = None
        try:
            if chunk_size is None:
                result = self._process_lines(lines, hash_value, hash_type, show_progress=True)
            else:
                # Process lines in chunks using ThreadPoolExecutor if chunk_size is provided
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    futures = []
                    for i in range(0, len(lines), chunk_size):
                        chunk = lines[i:i + chunk_size]
                        futures.append(executor.submit(self._process_lines, chunk, hash_value, hash_type))

                    for future in tqdm(as_completed(futures), total=len(futures), desc="Cracking"):
                        try:
                            result = future.result()
                            if result:
                                executor.shutdown(wait=False)
                                break
                        except Exception as e:
                            decryptXLogger.error(f"⚠️ Error processing a chunk: {e}")
        except KeyboardInterrupt:
            decryptXLogger.warning("⚡️ KeyboardInterrupt detected! Stopping the process...")
            # Clean up resources or notify threads to stop
            executor.shutdown(wait=False, cancel_futures=True)
            return None
        except Exception as e:
            decryptXLogger.error(f"🔥 Unexpected error: {e}")
        return result
    
    def crack_zip(self, zip_file, wordlist):
        """
        Attempt to crack a password-protected ZIP file using a wordlist.

        Args:
            zip_file (str): Path to the ZIP file to crack.
            wordlist (str): Path to the password list (wordlist) to use for cracking.

        Returns:
            str: The password if found, otherwise None.

        Raises:
            FileNotFoundError: If the ZIP file or the wordlist is not found.
            pyzipper.BadZipFile: If the ZIP file is not a valid ZIP file.
            Exception: If an unexpected error occurs.
        """
        try:
            # Open the ZIP file for cracking with AES decryption support
            with pyzipper.AESZipFile(zip_file) as zipf:
                zipf.setpassword(None)  # Start without a password
                decryptXLogger.info(f"🔓 Attempting to crack the ZIP file: {zip_file} using wordlist: {wordlist}")
                with open(wordlist, 'rb') as f:
                    passwords = f.readlines()
                    
                    # Iterate through the passwords in the wordlist
                    for password in tqdm(passwords, desc="Decrypting ZIP", unit="password"):
                        try:
                            zipf.pwd = password.strip()
                            zipf.extractall()
                            password = password.decode().strip()
                            decryptXLogger.info(f"🎯 Password found for ZIP: {password}")
                            return password
                        
                        except (RuntimeError, pyzipper.BadZipFile) as e:
                            decryptXLogger.debug(f"❌ Failed with password: {password.strip().decode()} - {str(e)}")
                            continue

        except FileNotFoundError:
            decryptXLogger.error(f"💥 The ZIP file '{zip_file}' does not exist. Check the path and try again.")
            raise
        except pyzipper.BadZipFile:
            decryptXLogger.error(f"💥 The file '{zip_file}' is not a valid ZIP file. Are you sure it's a proper ZIP?")
            raise
        except Exception as e:
            decryptXLogger.error(f"⚠️ Unexpected error while cracking ZIP: {str(e)}")
        decryptXLogger.info("❌ No matching password found in the wordlist.")
        return None

