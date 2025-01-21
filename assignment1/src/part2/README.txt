Encryption: 
Run FileEncryptor.java with the following arguments
1. "enc"
2. a key for the encryption
3. path to file being encrypted
4. path to location where ciphertext should be saved

Example:
java FileEncryptor.java enc gYIVDM6j2kAfoQj4gF7QHw== plaintext.txt ciphertext.enc

Decryption:
Run FileEncryptor.java with the following arguments
1. "dec"
2. key used for the encryption
4. path to file being decrypted
5. path to location where decrypted text should be saved

Example: java FileEncryptor.java dec gYIVDM6j2kAfoQj4gF7QHw== ciphertext.enc decoded.txt