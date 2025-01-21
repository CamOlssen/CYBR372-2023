Encryption: 
Run FileEncryptor.java with the following arguments
1. "enc"
2. path to file being encrypted
3. path to location where ciphertext should be saved

Example:
java FileEncryptor.java enc plaintext.txt ciphertext.enc

Encryption with custom seed:
Run FileEncryptor.java with the following arguments
1. "enc"
2. path to file being encrypted
3. path to location where ciphertext should be saved

Example:
java FileEncryptor.java enc plaintext.txt ciphertext.enc 87654321

Decryption:
Run FileEncryptor.java with the following arguments
1. "dec"
2. secret key output by the encryption
3. IV output by the encryption
4. path to file being decrypted
5. path to location where decrypted text should be saved

Example: java FileEncryptor.java dec gYIVDM6j2kAfoQj4gF7QHw== RRps1lRtmguj0E1WKzZH7Q== ciphertext.enc decoded.txt