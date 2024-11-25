from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import logging
import bcrypt
from passlib.hash import scrypt, argon2
import argparse
from tqdm import tqdm
import os
import gzip

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class HashCracker:
    """Class to crack hashes using a password list."""
    
    DEFAULT_WORDLIST = '/usr/share/wordlists/rockyou.txt'

    def __init__(self):
        """Initialize the HashCracker class with supported hash types."""
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

    def _ensure_wordlist_ready(self):
        """Ensure the wordlist is ready and decompressed."""
        wordlist_path = self.DEFAULT_WORDLIST
        compressed_path = f"{wordlist_path}.gz"

        if not os.path.exists(wordlist_path):
            if os.path.exists(compressed_path):
                logging.info(f"Decompressing {compressed_path}...")
                with gzip.open(compressed_path, 'rb') as gz_file:
                    with open(wordlist_path, 'wb') as out_file:
                        out_file.write(gz_file.read())
                logging.info(f"{compressed_path} decompressed to {wordlist_path}.")
            else:
                raise FileNotFoundError(f"Wordlist not found: {wordlist_path} or {compressed_path}")
        return wordlist_path
    
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
            # Convert both password and hash to bytes
            password_bytes = password.encode('latin-1')
            hash_bytes = hash_value.encode('latin-1')
            # Use bcrypt's checkpw function to verify the password against the hash
            return bcrypt.checkpw(password_bytes, hash_bytes)
        except Exception as ex:
            return False

    def _count_total_lines(self, wordlist_path):
        """Count total lines in the wordlist for progress tracking."""
        with open(wordlist_path, 'r', encoding='latin-1') as f:
            return sum(1 for _ in f)

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
                logging.debug(f"_process_lines: Exception for password '{password}': {ex}")
                continue
        return None
    
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
            raise ValueError(f"Invalid hash type: {hash_type}. Supported types are: {list(self.supported_hashes)}")
        
        wordlist_path = self._ensure_wordlist_ready()
        total_lines = self._count_total_lines(wordlist_path)

        logging.info(f"Attempting to crack hash '{hash_value}' using '{hash_type}' with {total_lines} passwords.")
        
        with open(wordlist_path, 'r', encoding='latin-1') as file:
            lines = file.readlines()

        result = None
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
                    result = future.result()
                    if result:
                        executor.shutdown(wait=False)
        return result

def main():
    """Main function for the hash cracking script."""
    parser = argparse.ArgumentParser(description="Crack a password hash.")
    parser.add_argument('hash', help='The hash to crack')
    parser.add_argument('--hash-type', help='The type of hash to use', default='md5')
    parser.add_argument('--max-workers', type=int, default=4, help='Number of threads for parallel processing')
    parser.add_argument('--chunk-size', type=int, help='Number of passwords per thread chunk (leave empty for sequential)')
    args = parser.parse_args()

    cracker = HashCracker()
    try:
        result = cracker.crack_hash(args.hash, args.hash_type, args.max_workers, args.chunk_size)
        if result:
            logging.info(f"[+] Password found: {result}")
        else:
            logging.info("[-] No matches found.")
    except ValueError as e:
        logging.error(f"Error: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
