import argparse
from decryptx.decryptx import DecryptX
from decryptx.utils.logger import decryptXLogger

def main():
    """
    Main entry point for the DecryptX utility.

    This tool allows users to crack password hashes or decrypt protected ZIP files 
    using wordlist-based attacks. It supports various hash algorithms and multithreading 
    for enhanced performance.

    Usage:
        python decryptx.py --mode <hash|zip> <target> [options]

    Modes:
        hash: Crack a password hash (requires --hash-type).
        zip: Decrypt a password-protected ZIP file.

    Command-Line Arguments:
        --mode (str): Operation mode: 'hash' to crack a hash, or 'zip' to crack a ZIP file (required).
        <target>: For 'hash' mode, provide the hash to crack. For 'zip' mode, provide the ZIP file path.
        --hash-type (str): For 'hash' mode, specify the hash algorithm (default: md5).
        --max-workers (int): Number of threads for parallel processing (default: 4).
        --chunk-size (int): Number of passwords per thread chunk. Leave empty for sequential processing.
        --wordlist (str): Path to a custom wordlist. If not provided, the default wordlist will be used.

    Returns:
        None. Outputs the result to the console.

    Logging:
        [+] Indicates a successfully cracked password or ZIP file.
        [-] Indicates no matches were found.
        [!] Logs errors, including invalid input or unexpected issues.
    """
    parser = argparse.ArgumentParser(
        description="🔓 DecryptX: Crack hashes or decrypt ZIP files for security assessments."
    )
    parser.add_argument(
        '--mode',
        required=True,
        choices=['hash', 'zip'],
        help="Operation mode: 'hash' to crack a password hash or 'zip' to crack a protected ZIP file."
    )
    parser.add_argument('target', help="The hash to crack (in 'hash' mode) or the path to the ZIP file (in 'zip' mode).")
    parser.add_argument(
        '--hash-type',
        help='The type of hash algorithm to use (e.g., md5, sha256, bcrypt). Default is md5. (Only for hash mode)',
        default='md5'
    )
    parser.add_argument(
        '--max-workers',
        type=int,
        default=4,
        help='Number of threads to use for parallel processing (default: 4). (Only for hash mode)'
    )
    parser.add_argument(
        '--chunk-size',
        type=int,
        help='Number of passwords to process per thread chunk. Leave empty for sequential processing. (Only for hash mode)'
    )
    parser.add_argument(
        '--wordlist',
        type=str,
        help='Path to a custom wordlist. If not provided, the default wordlist will be used.'
    )
    args = parser.parse_args()

    cracker = DecryptX(wordlist_path=args.wordlist)

    if args.mode == 'hash':
        # Crack the hash
        try:
            decryptXLogger.info("🚀 Starting hash cracking process...")
            result = cracker.crack_hash(
                hash_value=args.target,
                hash_type=args.hash_type,
                max_workers=args.max_workers,
                chunk_size=args.chunk_size
            )
            if result:
                decryptXLogger.info(f"[+] Password found for hash: {result} 🔓")
            else:
                decryptXLogger.warning("[-] No matches found for the hash. 🔒")
        except ValueError as e:
            decryptXLogger.error(f"[!] Error: {e} ❌")
        except Exception as e:
            decryptXLogger.critical(f"[!] An unexpected error occurred: {e} 💥")

    elif args.mode == 'zip':
        try:
            decryptXLogger.info("🚀 Starting ZIP cracking process...")
            result = cracker.crack_zip(args.target)
            if result:
                decryptXLogger.info(f"[+] Password found for ZIP file: {result} 🔓")
            else:
                decryptXLogger.warning("[-] No matches found for the ZIP file. 🔒")
        except FileNotFoundError as e:
            decryptXLogger.error(f"[!] ZIP file error: {e} ❌")
        except Exception as e:
            decryptXLogger.critical(f"[!] An unexpected error occurred while cracking the ZIP file: {e} 💥")
    else:
        decryptXLogger.error("[!] Invalid mode specified. Use 'hash' or 'zip'. ❌")

if __name__ == "__main__":
    main()