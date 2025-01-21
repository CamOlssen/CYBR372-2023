Encryption: 
Run FileEncryptor.java with the following arguments
1. "enc"
2. a password for the encryption
3. path to file being encrypted
4. path to location where ciphertext should be saved

Example:
java FileEncryptor.java enc mypassword plaintext.txt ciphertext.enc

Decryption:
Run FileEncryptor.java with the following arguments
1. "dec"
2. the password used to encrypt the file
3. path to file being decrypted
4. path to location where decrypted text should be saved

Example: java FileEncryptor.java dec mypassword ciphertext.enc decoded.txt