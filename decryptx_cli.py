import argparse
from decryptx.decryptx import DecryptX
from decryptx.utils.logger import decryptXLogger

def main():
    """Main function for the hash cracking script."""
    parser = argparse.ArgumentParser(description="Crack a password hash.")
    parser.add_argument('hash', help='The hash to crack')
    parser.add_argument('--hash-type', help='The type of hash to use', default='md5')
    parser.add_argument('--max-workers', type=int, default=4, help='Number of threads for parallel processing')
    parser.add_argument('--chunk-size', type=int, help='Number of passwords per thread chunk (leave empty for sequential)')
    args = parser.parse_args()

    cracker = DecryptX()
    try:
        result = cracker.crack_hash(args.hash, args.hash_type, args.max_workers, args.chunk_size)
        if result:
            decryptXLogger.info(f"[+] Password found: {result}")
        else:
            decryptXLogger.info("[-] No matches found.")
    except ValueError as e:
        decryptXLogger.error(f"Error: {e}")
    except Exception as e:
        decryptXLogger.error(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()