import hashlib
import logging
import bcrypt
from passlib.hash import scrypt, argon2
import argparse
from tqdm import tqdm
import os
import gzip

# Basic logging configuration
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
            'bcrypt': bcrypt.hashpw,
            'scrypt': scrypt.verify,
            'argon2': argon2.verify
        }


    def crack_hash(self, hash_value, hash_type):
        """
        Attempt to crack a hash using the default password list.

        Args:
            hash_value (str): The hash to crack.
            hash_type (str): The type of hash to use.

        Returns:
            str: The password that matches the hash if found, otherwise None.
        
        Raises:
            ValueError: If the hash type is not supported.
        """
        # Ensure the hash type is supported
        if hash_type not in self.supported_hashes:
            raise ValueError(f'Invalid hash type: {hash_type}. Supported types are: {list(self.supported_hashes)}')

        # Get the path to the wordlist
        wordlist_path = self._ensure_wordlist_ready()

        total_lines = self._count_total_lines(wordlist_path)

        logging.info(f"Attempting to crack hash '{hash_value}' using '{hash_type}' with a list of {total_lines} passwords.")

        # Open the wordlist and process line by line
        with open(wordlist_path, 'r', encoding='latin-1') as file:
            for line in tqdm(file, desc="Cracking", total=total_lines):
                password = line.strip()

                # Handle special hash types
                if hash_type in ['bcrypt', 'scrypt', 'argon2']:
                    try:
                        if self.supported_hashes[hash_type](password, hash_value):
                            return password
                    except Exception as e:
                        logging.debug(f"Error verifying password '{password}' with {hash_type}: {e}")
                else:
                    # Handle general hash types
                    hash_function = self.supported_hashes[hash_type]
                    if hash_function(password.encode()).hexdigest() == hash_value:
                        return password

        return None
    

    def _count_total_lines(wordlist_path):
        # Count the total lines in the wordlist for progress tracking
        total_lines = None
        try:
            total_lines = sum(1 for _ in open(wordlist_path, 'r', encoding='latin-1'))
        except FileNotFoundError:
            logging.error(f"Wordlist file not found: {wordlist_path}")
        return total_lines
            
    
    def _ensure_wordlist_ready(self):
        """
        Ensures the rockyou.txt wordlist is available and decompressed.

        Returns:
            str: Path to the wordlist file.
        """
        wordlist_path = self.DEFAULT_WORDLIST
        compressed_path = f"{wordlist_path}.gz"

        # Check if the decompressed wordlist is available
        if not os.path.exists(wordlist_path):
            # If compressed version exists, decompress it
            if os.path.exists(compressed_path):
                logging.info(f"Decompressing {compressed_path}...")
                with gzip.open(compressed_path, 'rb') as gz_file:
                    with open(wordlist_path, 'wb') as out_file:
                        out_file.write(gz_file.read())
                logging.info(f"{compressed_path} decompressed to {wordlist_path}.")
            else:
                raise FileNotFoundError(f"Wordlist not found: {wordlist_path} or {compressed_path}")

        return wordlist_path

def main():
    """Main function for the hash cracking script."""
    parser = argparse.ArgumentParser(description="Crack a password hash.")
    parser.add_argument('hash', help='The hash to crack')
    parser.add_argument('--hash-type', help='The type of hash to use', default='md5')
    args = parser.parse_args()

    cracker = HashCracker()
    try:
        result = cracker.crack_hash(args.hash, args.hash_type)
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