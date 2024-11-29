# 🔐 **DecryptX: Advanced Hash and Password Security Assessment Tool** 🛠️  

DecryptX is a professional-grade ethical hacking tool designed for cybersecurity experts and penetration testers. Specializing in analyzing password hashes and encrypted ZIP files, it allows users to assess the robustness of their security implementations. With support for standard hash algorithms and encrypted archives, DecryptX combines precision, speed, and reliability to identify vulnerabilities before attackers do.  

🙏 I would like to express my sincere gratitude to [Santiago Hernández, a leading expert in Cybersecurity and Artificial Intelligence](https://www.udemy.com/user/shramos/). His outstanding course on **Cybersecurity and Ethical Hacking**, available on Udemy, was instrumental in the development of this project. The insights and techniques I gained from his course were invaluable in guiding my approach to cybersecurity practices. Thank you for sharing your knowledge and expertise!

> ⚠️ **Disclaimer**: This tool is intended for educational and ethical hacking purposes only. Always ensure you have proper authorization before testing any systems.

<p align="center">
  <img src="https://img.shields.io/badge/Kali_Linux-557C94?style=for-the-badge&logo=kali-linux&logoColor=white" />
  <img src="https://img.shields.io/badge/Python-FFD43B?style=for-the-badge&logo=python&logoColor=blue" />
</p>

<p align="center">
  <img src="doc/screenshots/picture_1.PNG" />
</p>

## ✨ **Key Features**  

- 🔑 **Password Cracking**  
  Efficiently recover lost or forgotten passwords using a combination of brute-force and dictionary-based attacks.  
  - **Brute-Force Attack**: Attempts all possible combinations of characters within a specified range.  
  - **Dictionary Attack**: Leverages wordlists, including custom and pre-built ones like `rockyou.txt`, to match against potential passwords.  
  - **Multithreading Support**: Maximizes cracking speed by utilizing modern multi-core CPUs.  

- 🔐 **Hash Cracking**  
  DecryptX supports a wide array of modern and legacy hash algorithms, allowing security professionals to test for weaknesses in password storage mechanisms.  
  - **Supported Algorithms**: Includes MD5, SHA-1, SHA-2 (SHA-224, SHA-256, SHA-384, SHA-512), SHA-3, bcrypt, argon2, and more.  
  - **Customizable Workflow**: Allows you to select the hash type and tailor the cracking approach to specific security assessments.  
  - **Progress Tracking**: Provides real-time feedback with progress bars to monitor the cracking process.  

- 📂 **Encrypted ZIP Cracking**  
  Quickly bypass ZIP file password protections to access encrypted content.  
  - **AES Encrypted ZIPs**: Supports modern AES-encrypted ZIP files often encountered in enterprise settings.  
  - **Custom Dictionary**: Use tailored wordlists for improved success rates in password recovery.  
  - **Error Handling**: Automatically skips invalid attempts or corrupted entries to ensure uninterrupted processing.  
  - **Safe Extraction**: Avoids overwriting files by verifying successful decryption before extraction.  

Each feature is designed to handle real-world scenarios with efficiency and accuracy, ensuring cybersecurity professionals have a robust toolset for ethical hacking and vulnerability assessments.

<p align="center">
  <img src="doc/screenshots/picture_2.PNG" />
</p>

## 🔧 **Supported Algorithms**  

DecryptX supports a wide range of algorithms, including modern standards and legacy ones often required for specific security assessments:  

### **Modern Algorithms:**  

- **BLAKE2 (`blake2b`, `blake2s`)**  
  Fast and secure, designed to replace SHA-2.  

- **SHA-2 (`sha1`, `sha224`, `sha256`, `sha384`, `sha512`)**  
  Widely used in secure protocols like HTTPS and digital signature systems.  

- **SHA-3 (`sha3_224`, `sha3_256`, `sha3_384`, `sha3_512`)**  
  Based on **Keccak**, offering advanced resistance to collision attacks.  

- **RIPEMD-160 (`ripemd160`)**  
  A cryptographic alternative to MD5 and SHA-1, used in blockchain and other environments.  

- **bcrypt**  
  Designed for password protection, with support for scalable cost factors.  

- **scrypt**  
  Resistant to hardware attacks (ASIC), ideal for systems handling sensitive passwords.  

- **argon2**  
  A modern and secure password hashing algorithm, winner of **PHC 2015**.  

### **Legacy Algorithms:**  

- **MD5 (`md5`)**  
  Considered insecure for most modern applications but still required in older systems.  

- **MD4 (`md4`)**  
  Predecessor to MD5, even less secure, occasionally used in very old applications.  

- **SHA-1 Variant (`sha1_v2`)**  
  A custom version of SHA-1, used for specific applications.  

- **CRC32 (`crc32`)**  
  More suited for integrity verification than cryptographic security.

<p align="center">
  <img src="doc/screenshots/picture_3.PNG" />
</p>

## 📜 **Prerequisites**  

Before using **DecryptX**, make sure you have the following dependencies installed:

- 🐍 **Python 3.8+**  
  DecryptX requires Python version 3.8 or higher. You can download the latest version of Python from the official [Python website](https://www.python.org/downloads/).

- 📦 **Required Python Libraries**  
  DecryptX utilizes a set of Python libraries for functionality such as cryptographic hashing, password cracking, progress tracking, and ZIP file handling. Below are the required libraries that you need to install:

  - **`bcrypt==4.2.1`**  
    A fast and secure password hashing library used for working with bcrypt hashes, commonly used in modern password storage systems. This library is essential for verifying bcrypt hashed passwords.
  
  - **`tqdm==4.67.1`**  
    A fast, extensible progress bar library for Python. DecryptX uses `tqdm` to display progress bars during cracking operations, making it easier to track the status of hash and ZIP file cracking processes.
  
  - **`passlib==1.7.4`**  
    A comprehensive password hashing library. `Passlib` is used in DecryptX to handle various hashing algorithms, including bcrypt and Argon2, providing secure password hashing capabilities.
  
  - **`colorama==0.4.6`**  
    A cross-platform library to output colored terminal text. This library is used for enhanced logging and error message formatting, making the tool's output more user-friendly and visually appealing.
  
  - **`pyzipper==0.3.6`**  
    A powerful library for reading and writing password-protected ZIP files with support for AES encryption. `pyzipper` enables DecryptX to crack encrypted ZIP files by trying password combinations from a wordlist.
  
  - **`pycryptodome==3.21.0`**  
    A self-contained Python package for cryptographic operations. `pycryptodome` provides support for various legacy hash algorithms like MD4, RIPEMD-160, and others, enabling DecryptX to handle both modern and older hashing methods.

<p align="center">
  <img src="doc/screenshots/picture_4.PNG" />
</p>


### Installing Dependencies

To install all required libraries, you can use the following command:

```bash
pip install -r requirements.txt
```

This will automatically install all the dependencies listed in the requirements.txt file for you.


## ⚠️ **Legal Notice**  

DecryptX should only be used on systems where you have permission to perform tests. Unauthorized use may violate local or international laws, and the author of this tool is not responsible for misuse.  


