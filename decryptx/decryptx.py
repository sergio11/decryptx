from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from decryptx.hash_verifier import HashVerifier
import pyzipper
import os
import gzip
from decryptx.utils.logger import decryptXLogger
from decryptx import __version__

class DecryptX:
    """
    DecryptX is a powerful tool designed for ethical hacking, penetration testing, 
    and security assessments. It is focused on evaluating the strength of password 
    hashes and encrypted ZIP files. DecryptX supports a wide range of cryptographic 
    hash algorithms and provides features for identifying weaknesses in password security.

    It is particularly useful for cybersecurity professionals and penetration testers 
    looking to evaluate vulnerabilities in password management systems.

    Attributes:
        DEFAULT_WORDLIST (str): The path to the default wordlist file (typically 'rockyou.txt'),
                                 which is used for password cracking or brute force attacks.
        wordlist_path (str): The path to the wordlist to be used during cracking attempts. 
                             If not provided, the default is used.
        hash_verifier (HashVerifier): An instance of the HashVerifier class used to verify password hashes.
    """

    DEFAULT_WORDLIST = '/usr/share/wordlists/rockyou.txt'

    def __init__(self, wordlist_path=None):
        """
        Initializes the DecryptX tool with the specified wordlist for password cracking.

        If no wordlist path is provided, the default wordlist ('rockyou.txt') is used.

        Args:
            wordlist_path (str, optional): The file path to the wordlist used for cracking password hashes.
                                           If not specified, it defaults to '/usr/share/wordlists/rockyou.txt'.
        
        Attributes:
            wordlist_path (str): The file path of the wordlist to use.
            hash_verifier (HashVerifier): A HashVerifier instance for verifying password hashes.
        """
        self.wordlist_path = wordlist_path or self.DEFAULT_WORDLIST
        self.hash_verifier = HashVerifier()
        self._print_banner()


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
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    futures = []
                    for i in range(0, len(lines), chunk_size):
                        chunk = lines[i:i + chunk_size]
                        futures.append(executor.submit(self._process_lines, chunk, hash_value, hash_type))

                    for future in tqdm(as_completed(futures), total=len(futures), desc="🔓 Cracking Hash"):
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

    def crack_zip(self, zip_file, max_workers=4, chunk_size=None):
        """
        Attempt to crack a password-protected ZIP file using a wordlist with concurrency.

        Args:
            zip_file (str): Path to the ZIP file to crack.
            max_workers (int): Number of threads to use for parallel processing.
            chunk_size (int): Number of passwords per chunk. Adjust according to the size of the wordlist.

        Returns:
            str: The password if found, otherwise None.

        Raises:
            FileNotFoundError: If the ZIP file or the wordlist is not found.
            pyzipper.BadZipFile: If the ZIP file is not a valid ZIP file.
            Exception: If an unexpected error occurs.
        """
        try:
            result = None
            # Open the ZIP file for cracking with AES decryption support
            with pyzipper.AESZipFile(zip_file) as zipf:
                zipf.setpassword(None)  # Start without a password
                decryptXLogger.info(f"🔓 Attempting to crack the ZIP file: {zip_file} using wordlist: {self.wordlist_path}")
                
                with open(self.wordlist_path, 'r', encoding='latin-1') as f:
                    passwords = f.readlines()

                if chunk_size is None:
                    result = self._crack_zip_chunk(zipf, passwords, show_progress=True)
                else:
                    chunks = [passwords[i:i + chunk_size] for i in range(0, len(passwords), chunk_size)]
                    with ThreadPoolExecutor(max_workers=max_workers) as executor:
                        futures = []
                        for chunk in chunks:
                            futures.append(executor.submit(self._crack_zip_chunk, zipf, chunk))
                        for future in tqdm(as_completed(futures), total=len(futures), desc="🔓 Breaching ZIP Security", unit="chunk"):
                            try:
                                result = future.result()
                                if result:
                                    executor.shutdown(wait=False)
                                    break
                            except Exception as e:
                                decryptXLogger.error(f"⚠️ Error processing a chunk: {e}")
        except FileNotFoundError:
            decryptXLogger.error(f"💥 The ZIP file '{zip_file}' does not exist. Check the path and try again.")
            raise
        except pyzipper.BadZipFile:
            decryptXLogger.error(f"💥 The file '{zip_file}' is not a valid ZIP file. Are you sure it's a proper ZIP?")
            raise
        except Exception as e:
            decryptXLogger.error(f"⚠️ Unexpected error while cracking ZIP: {str(e)}")
        
        decryptXLogger.info("❌ No matching password found in the wordlist.")
        return result

    def _crack_zip_chunk(self, zipf, password_chunk, show_progress=False):
        """
        Attempt to crack a password-protected ZIP file using a chunk of passwords.

        Args:
            zipf (pyzipper.AESZipFile): The opened ZIP file object.
            password_chunk (list): List of passwords to attempt in this chunk.

        Returns:
            str: The password if found, otherwise None.
        """
        iterable = tqdm(password_chunk, desc="🔓 Breaching ZIP Security", unit="password") if show_progress else password_chunk
        password = None
        for password in iterable:
            try:
                password = password.strip()
                zipf.pwd = password.encode('latin-1')
                zipf.extractall()
                break
            except (RuntimeError, pyzipper.BadZipFile, Exception) as e:
                continue
        return password
    
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
        """
        Process the wordlist lines to crack the hash.
        """
        iterable = tqdm(lines, desc="🔓 Cracking Hash", unit="password") if show_progress else lines
        for password in iterable:
            password = password.strip()
            try:
                if self.hash_verifier.verify_hash(password, hash_value, hash_type):
                    return password
            except Exception as ex:
                decryptXLogger.debug(f"⚠️ Error verifying password '{password}': {ex}")
        return None
    
    def _print_banner(self):
        banner = f"""
            ██████████                                                      █████    █████ █████
            ░░███░░░░███                                                   ░░███    ░░███ ░░███ 
            ░███   ░░███  ██████   ██████  ████████  █████ ████ ████████  ███████   ░░███ ███  
            ░███    ░███ ███░░███ ███░░███░░███░░███░░███ ░███ ░░███░░███░░░███░     ░░█████   
            ░███    ░███░███████ ░███ ░░░  ░███ ░░░  ░███ ░███  ░███ ░███  ░███       ███░███  
            ░███    ███ ░███░░░  ░███  ███ ░███      ░███ ░███  ░███ ░███  ░███ ███  ███ ░░███ 
            ██████████  ░░██████ ░░██████  █████     ░░███████  ░███████   ░░█████  █████ █████
            ░░░░░░░░░░    ░░░░░░   ░░░░░░  ░░░░░       ░░░░░███  ░███░░░     ░░░░░  ░░░░░ ░░░░░ 
                                                    ███ ░███  ░███                           
                                                    ░░██████   █████                          
                                                    ░░░░░░   ░░░░░                           
        DecryptX: Advanced Hash and Password Security Assessment Tool 🔓🖤 (Version: {__version__})
        """
        print(banner)
    




