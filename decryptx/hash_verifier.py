import hashlib
import bcrypt
from passlib.hash import scrypt, argon2
from decryptx.utils.logger import decryptXLogger

class HashVerifier:
    """
    The HashVerifier class is responsible for verifying the correctness of a password 
    against various hash values. It supports a wide range of hash algorithms including
    both modern and legacy options, such as bcrypt, scrypt, and MD4.

    Attributes:
        supported_hashes (dict): A dictionary mapping hash types (as strings) to their corresponding 
                                  hash functions or verification methods.

    Methods:
        verify_hash(password, hash_value, hash_type):
            Verifies if the given password matches the specified hash value using the appropriate hash function.
        _verify_md4(password, hash_value):
            Verifies if the password matches the provided MD4 hash.
        _verify_ripemd160(password, hash_value):
            Verifies if the password matches the provided RIPEMD-160 hash.
        _verify_crc32(password, hash_value):
            Verifies if the password matches the provided CRC32 hash.
        _verify_bcrypt(password, hash_value):
            Verifies if the password matches the provided bcrypt hash.
    """

    def __init__(self):
        """
        Initializes the HashVerifier class with a predefined set of supported hash algorithms.

        The supported algorithms include both cryptographic and non-cryptographic hashes, 
        such as MD5, SHA-1, bcrypt, scrypt, and CRC32.

        Raises:
            ImportError: If any required external libraries (e.g., `pycryptodome`, `bcrypt`, `argon2`) are not installed.
        """
        self.supported_hashes = {
            'blake2b': hashlib.blake2b,
            'blake2s': hashlib.blake2s,
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha224': hashlib.sha224,
            'sha256': hashlib.sha256,
            'sha384': hashlib.sha384,
            'sha3_224': hashlib.sha3_224,
            'sha3_256': hashlib.sha3_256,
            'sha3_384': hashlib.sha3_384,
            'sha3_512': hashlib.sha3_512,
            'sha512': hashlib.sha512,
            'bcrypt': self._verify_bcrypt,
            'scrypt': scrypt.verify,
            'argon2': argon2.verify,
            # Additional modern hashes
            'ripemd160': self._verify_ripemd160,
            # Legacy hash algorithms (less secure but sometimes still needed)
            'sha1_v2': hashlib.new('sha1'),
            'md4': self._verify_md4,  # Less common MD4 algorithm, requires pycryptodome
            'crc32': self._verify_crc32,  # Cyclic redundancy check, not a secure hash
        }

    def verify_hash(self, password, hash_value, hash_type):
        """
        Verifies if the given password matches the specified hash value using the appropriate hash function.

        Args:
            password (str): The plaintext password to verify.
            hash_value (str): The hash value (in hexadecimal string format) to compare against.
            hash_type (str): The hash algorithm to use (e.g., 'sha256', 'bcrypt').

        Returns:
            bool: True if the password matches the hash value, otherwise False.

        Raises:
            ValueError: If the provided hash type is not supported.
        """
        if hash_type not in self.supported_hashes:
            decryptXLogger.error(f"💀 Unsupported hash type: {hash_type}")
            raise ValueError(f"Unsupported hash type: {hash_type}")

        hash_function = self.supported_hashes[hash_type]
        
        if callable(hash_function):
            return hash_function(password, hash_value)
        
        password_bytes = password.encode('latin-1')
        return hash_function(password_bytes).hexdigest() == hash_value


    def _verify_md4(self, password, hash_value):
        """
        Verifies if the given password matches the MD4 hash.

        Args:
            password (str): The plaintext password.
            hash_value (str): The expected MD4 hash value.

        Returns:
            bool: True if the MD4 hash of the password matches the given hash value, otherwise False.

        Raises:
            ImportError: If the `pycryptodome` library is not installed.
        """
        try:
            from Crypto.Hash import MD4
            password_bytes = password.encode('latin-1')
            md4_hash = MD4.new(password_bytes).hexdigest()
            return md4_hash == hash_value
        except Exception:
            return False
    
    def _verify_ripemd160(self, password, hash_value):
        """
        Verifies if the given password matches the RIPEMD-160 hash.

        Args:
            password (str): The plaintext password.
            hash_value (str): The expected RIPEMD-160 hash value.

        Returns:
            bool: True if the RIPEMD-160 hash of the password matches the given hash value, otherwise False.

        Raises:
            ImportError: If the `pycryptodome` library is not installed.
        """
        try:
            from Crypto.Hash import RIPEMD160
            password_bytes = password.encode('latin-1')
            ripemd160_hash = RIPEMD160.new(password_bytes).hexdigest()
            return ripemd160_hash == hash_value
        except Exception:
            return False

    def _verify_crc32(self, password, hash_value):
        """
        Verifies if the given password matches the CRC32 hash.

        Args:
            password (str): The plaintext password.
            hash_value (str): The expected CRC32 hash value (in hexadecimal string format).

        Returns:
            bool: True if the CRC32 hash of the password matches the given hash value, otherwise False.

        Notes:
            CRC32 is not a secure hashing algorithm and should not be used for password security.
        """
        import zlib
        password_bytes = password.encode('latin-1')
        crc32_hash = format(zlib.crc32(password_bytes) & 0xFFFFFFFF, '08x')
        return crc32_hash == hash_value

    def _verify_bcrypt(self, password, hash_value):
        """
        Verifies if the given password matches the bcrypt hash.

        Args:
            password (str): The plaintext password.
            hash_value (str): The bcrypt hash value.

        Returns:
            bool: True if the password matches the bcrypt hash, otherwise False.

        Raises:
            ImportError: If the `bcrypt` library is not installed.
        """
        try:
            password_bytes = password.encode('latin-1')
            hash_bytes = hash_value.encode('latin-1')
            if bcrypt.checkpw(password_bytes, hash_bytes):
                return True
            else:
                return False
        except Exception as ex:
            decryptXLogger.error(f"❌ Error verifying bcrypt password: {password}. Exception: {ex}")
            return False