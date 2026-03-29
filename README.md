🇵🇱 [Polish version](README_PL.md)

## 🔐 File Encryption and Decryption System with Data Integrity Verification

The system allows encryption and decryption of various types of files (text, images, audio, video, etc.) using selected symmetric and asymmetric cryptographic algorithms. Additionally, it implements mechanisms for verifying data integrity.

---

## ✨ Features

- Encryption and decryption of various types of files (text, images, audio, video, etc.).
- Support for multiple cryptographic algorithms (AES, 3DES, XChaCha20, Threefish, RSA).
- Authenticated encryption and data integrity verification (AEAD, MAC, digital signatures).
- Support for both symmetric and asymmetric keys.
- Secure file deletion adapted to the storage type (HDD/SSD).
- Drag and drop file support.
- Operation progress bar with ETA and cancellation capability.
- Automatic detection of system light/dark theme.
- Integration of the progress bar with the Windows taskbar.

---

## 🛠️ Technologies

- Python 3.10.
- PyQt5 – graphical user interface (GUI).
- PyCryptodome – implementation of cryptographic algorithms.
- PySkein – implementation of the Skein cryptographic primitive (Threefish).
- psutil – system resource monitoring.
- PyInstaller – building executable files (.exe).

---

## 🔒 Security Notes

This project was created for educational and demonstration purposes. It presents the implementation of various cryptographic algorithms and mechanisms.

The application supports authenticated encryption modes (AEAD), message authentication codes (MAC), and digital signatures for verifying data integrity.

Secure file deletion mechanisms are implemented with consideration for different types of storage devices (HDD and SSD). Due to hardware-level mechanisms such as wear leveling on SSDs, complete physical data removal cannot always be guaranteed.

---

## 🎨 Application GUI

The system allows manual theme switching (light/dark). An Automatic Theme option is also available — when enabled, the application automatically adjusts the theme according to the system settings (Windows). The selected mode is saved and preserved between application launches. 

### 🔹 **Light Theme**

![GUI](https://github.com/user-attachments/assets/46a52655-3a0b-4e35-b979-f0874f4898bf)

### 🔹 **Dark Theme**

![GUI 2](https://github.com/user-attachments/assets/5ba3e581-c9e4-4e07-8920-0f12a9d5a41d)

---

## 🔑 Keys

### 🔹 **Symmetric**
- The key is generated and stored in a `.key` file.
- Example of a symmetric key file:

![Key](https://github.com/user-attachments/assets/03c99485-6229-4b68-b61a-a9663e879722)


### 🔹 **Asymmetric (RSA)**
- Keys are generated and stored in separate `.key` files.
- The public key is generated based on the private key.
- Example files containing the private and public keys:

![Keys](https://github.com/user-attachments/assets/709d0929-bada-4982-961f-aec14899e5a8)

---

## 🔢 Implemented Algorithms

![Algorithms](https://github.com/user-attachments/assets/051ef0d3-b792-4796-a95b-a96ac052528d)

### 🔹 **AES (Advanced Encryption Standard)**
- **Type:** Symmetric, block cipher.
- **Structure:** Feistel-like network with operations in the GF(2⁸) field.
- **Key lengths (bits):** 128, 192, 256.
- **Modes:** GCM (Galois/Counter Mode) – AEAD, EAX – AEAD, CBC (Cipher Block Chaining), ECB (Electronic Codebook).
- **Padding:** CBC and ECB modes – PKCS7.
- **File integrity verification**: AEAD modes (GCM, EAX) – MAC tag (Message Authentication Code).
- **Maximum file size**: 64 GB.

![AES](https://github.com/user-attachments/assets/d471c5da-253a-4017-aa52-801d49394546)

![AES 2](https://github.com/user-attachments/assets/4e2b6967-8f2d-4a4d-ac7a-c20eabd622ba)

![AES 3](https://github.com/user-attachments/assets/21f2882f-b421-4f76-a6df-4f9781620bab)

### 🔹 **3DES (Triple Data Encryption Standard)**
- **Type:** Symmetric, block cipher.
- **Structure:** Feistel network (DES applied three times in EDE scheme – encrypt-decrypt-encrypt).
- **Key lengths (bits):** 192.
- **Modes:** EAX – AEAD, CFB (Cipher Feedback), OFB (Output Feedback).
- **File integrity verification**: AEAD mode (EAX) – MAC tag.
- **Maximum file size**: EAX mode – 10 MB, CFB and OFB modes – 32 GB.

![3DES](https://github.com/user-attachments/assets/f27a811b-6881-4608-bbc4-6e7f2cd2407b)

![3DES 2](https://github.com/user-attachments/assets/e9f85a8a-e83a-4210-9f40-142394316903)

### 🔹 **XChaCha20**
- **Type:** Symmetric, stream cipher.
- **Structure:** XOR operations on matrices and vectors.
- **Key lengths (bits):** 256.
- **File integrity verification**: Poly1305 authentication tag.
- **Maximum file size**: practically unlimited (hundreds of TB to PB).

![XChaCha20](https://github.com/user-attachments/assets/cef22c90-5fcb-47ba-9531-128a6cd08bf8)

### 🔹 **Threefish**
- **Type:** Symmetric, block cipher.
- **Structure:** Modular and bitwise transformations.
- **Key lengths (bits):** 256, 512, 1024.
- **Modes:** Stream-like mode – XOR with keystream (similar to CTR – Counter).
- **File integrity verification**: Skein-MAC tag, keys derived using HKDF (HMAC-based Key Derivation Function) with SHA-256 (Secure Hash Algorithm 256-bit), EtM scheme (Encrypt-then-MAC).
- **Maximum file size**: practically unlimited (hundreds of TB to PB).

![Threefish](https://github.com/user-attachments/assets/8ebe010e-92e5-4e83-b48a-d8b4574447e3)

![Threefish 2](https://github.com/user-attachments/assets/c9634ca0-ce75-4e2e-810c-345443ad4bb5)

### 🔹 **RSA (Rivest–Shamir–Adleman)**
- **Type:** Asymmetric.
- **Structure:** Based on the computational difficulty of factoring large prime numbers.
- **Key lengths (bits):** 1024, 2048, 3072.
- **Padding:** PKCS#1 v1.5 (Public-Key Cryptography Standards), OAEP (Optimal Asymmetric Encryption Padding).
- **File integrity verification**: PSS signature (Probabilistic Signature Scheme) with SHA-256.
- **Maximum file size**: 1 MB.

![RSA](https://github.com/user-attachments/assets/873cd11a-37b3-4ba4-9af4-b867220ef0f5)

![RSA 2](https://github.com/user-attachments/assets/58e16bcc-928b-4c4f-a1c1-e38241a4f554)

![RSA 3](https://github.com/user-attachments/assets/b88c18db-b8bd-441f-b97b-0900ce8bca3f)

---

## 🗑️ Secure File Deletion

The system includes a mechanism for secure deletion of the original unencrypted file after encryption, adapted to the type of storage device with automatic detection (Windows). Secure deletion is optional and controlled from the GUI.

![Deletion](https://github.com/user-attachments/assets/a5e11866-935d-4423-b323-399a1ce23d8b)

### 🔹 **HDD (Hard Disk Drives)**
- The file is overwritten twice with random data in blocks of ~4 MiB. After each write operation, flush() and os.fsync() are executed to force writing to the storage device.
- A crypto-erase mechanism is used: a temporary file is created in the same directory, to which the original file is streamed and encrypted with a random key (AES-GCM, 256-bit key, 96-bit nonce) in ~1 MiB blocks. Each block is flushed and synchronized using fsync(). After encryption is completed, the key is securely wiped from memory. The temporary file replaces the original (os.replace), and the encrypted file is then deleted.

### 🔹 **SSD (Solid-State Drives)**
- Due to wear-leveling, overwriting does not guarantee physical data removal. Therefore, the crypto-erase method described above is primarily used.
- If available and enabled, the application attempts to invoke TRIM / Optimize-Volume (PowerShell) to release storage blocks (Windows).

---

## 📂 Additional Features

Preview of file paths and file sizes as well as key paths, with the ability to open the file or key location by double-clicking.

![Preview](https://github.com/user-attachments/assets/3498f8d0-9ea5-4b63-a977-5228fa6f7836)

Possibility to delete selected files and keys.

![Preview 2](https://github.com/user-attachments/assets/ac8f28d3-3769-4f0c-9330-d4e70405677d)

![Preview 3](https://github.com/user-attachments/assets/da0897e8-b38b-4ff8-ad85-717fad505e2e)

History of recently used files and keys.

![Preview 4](https://github.com/user-attachments/assets/ed4cba93-654f-4060-8520-b928dbab65d7)

Drag and drop support for files and keys directly into the appropriate fields in the GUI.

![Preview 5](https://github.com/user-attachments/assets/c1028026-34cd-4589-b1fe-27d0b1bb4a30)

---

## ⚙️ Encryption / Decryption

Encrypted files use the `.enc` extension.

![Encryption](https://github.com/user-attachments/assets/016528f5-c610-40fa-bb58-e320fa2cbead)

An integrity verification error is displayed during decryption if the encrypted file has been modified.

![Encryption 2](https://github.com/user-attachments/assets/15a0d35f-1e28-437e-b2e4-24b5d2ebd013)

---

## ⏳ Functional Progress Bar

The encryption/decryption operation can be cancelled at any time.

![Progress Bar](https://github.com/user-attachments/assets/b844c800-656c-471c-86d6-a294c0ff86f5)

The progress bar displays graphical and percentage progress along with ETA (Estimated Time of Arrival) — the estimated time remaining until the operation is completed.

![Progress Bar 2](https://github.com/user-attachments/assets/042cd932-cafa-445a-935b-58d618f007c1)

Integration of the progress bar with the Windows taskbar.

![Progress Bar 3](https://github.com/user-attachments/assets/4cfb24a2-45d5-4de5-9933-58d4be05b996)

---

## 🧰 Requirements and Dependency Installation

### 🔹 **Required libraries**

- `PyQt5` - graphical user interface.
- `PyCryptodome` - cryptographic algorithms.
- `PySkein` - Skein cryptographic primitive.
- `psutil` - system resource monitoring.

### 🔹 **Building the executable file**

  - `PyInstaller` - tool for creating `.exe` files.

  Build command:
  ``` bash
  pyinstaller --onefile --windowed --icon=icon.ico --name="File Encryption and Decryption" --add-data="icon.ico;." "main.py"
  ```
  
  Install PyInstaller:
  ```bash
  pip install PyInstaller==6.18.0
  ```

### 🔹 **Installing dependencies**
  You can install them individually with specific versions:
  ```bash
  pip install PyQt5==5.15.11 PyCryptodome==3.23.0 PySkein==1.0 psutil==7.2.2
  ```

  Or using `requirements.txt`:
  ```bash
  pip install -r requirements.txt
  ```

---

## 🧠 Future Improvements

- Introduction of a structured metadata header embedded within encrypted files, containing information about the selected algorithm, mode of operation, key parameters, and cryptographic settings. This would enable automatic configuration of decryption options upon file selection, improving usability and reducing the risk of incorrect parameter selection.
- Expansion of supported cryptographic algorithms, including modern and standardized solutions (e.g., additional AEAD modes, post-quantum algorithms in the future), to increase flexibility and adaptability of the system.
- Extension of configurable cryptographic parameters, such as nonce/IV size, tag length, key derivation settings (e.g., PBKDF2/Argon2), and security levels, allowing more advanced control for experienced users.
- Full implementation of digital signature mechanisms independent of encryption, enabling file authenticity verification (e.g., detached signatures, signature-only mode).
- Implementation of streaming-based encryption and decryption (chunked processing), allowing efficient handling of very large files without excessive RAM usage.
- Refactoring of the monolithic application architecture into modular components (separate files/modules for GUI, cryptography, file handling, and utilities), improving maintainability, scalability, and testability of the codebase.
- User interface improvements, including better UX consistency, enhanced feedback mechanisms, improved error handling, and more intuitive configuration flows.
- Internationalization (i18n) support with dynamic language switching, enabling the application to be used in multiple languages.

---

## 📄 License

This project is for educational and portfolio purposes.

---

📌 **Author:** *Michał Rusek (Vyroxes)*