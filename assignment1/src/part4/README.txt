Encryption: 
Run FileEncryptor.java with the following arguments
1. "enc"
2. Encryption type - AES or Blowfish
3. Key length - 	128, 192 or 256 for AES, 32 to 448 for Blowfish
4. a password for the encryption
5. path to file being encrypted
6. path to location where ciphertext should be saved

Example:
java FileEncryptor.java enc AES 256 mypassword plaintext.txt ciphertext.enc

Decryption:
Run FileEncryptor.java with the following arguments
1. "dec"
2. the password used to encrypt the file
4. path to file being decrypted
5. path to location where decrypted text should be saved

Example: java FileEncryptor.java dec mypassword ciphertext.enc decoded.txt

Info:
Run FileEncryptor.java with the following arguments
1. "info"
2. path to encrypted file

Example: java FileEncryptor.java info ciphertext.enc