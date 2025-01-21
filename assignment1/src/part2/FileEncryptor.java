package com.packtpub.crypto.section5.src.part2;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * CYBR373 Assignment 1 Part 2
 * Cam Olssen (300492582)
 */
public class FileEncryptor {
    private static final Logger LOG = Logger.getLogger(FileEncryptor.class.getSimpleName());

    private static final String ALGORITHM = "AES";
    private static final String CIPHER = "AES/CBC/PKCS5PADDING";

    /**
     * This method is called when the program is run. Creates a new FileEncryptor object and runs with provided arguments.
     * @param args - the arguments input by the user
     */
    public static void main(String[] args) {
        try {
            new FileEncryptor().run(args);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    /**
     * This method runs the first step of the algorithm by reading the user's input
     * @param args - arguments passed from main
     * @throws Exception - for exception handling
     */
    public void run(String[] args) throws Exception {
        if (Objects.equals(args[0], "enc")) {
            if (args.length != 4) {
                LOG.info("Invalid number of arguments!");
                System.exit(0);
            }
            //Generate the IV
            SecureRandom sr = new SecureRandom();
            byte[] initVector = new byte[16];
            sr.nextBytes(initVector); // 16 bytes IV

            //run encryption
            enc(Base64.getDecoder().decode(args[1]), initVector, args[2], args[3]);
        } else if (Objects.equals(args[0], "dec")) {
            if (args.length != 4) {
                LOG.info("Invalid number of arguments!");
                System.exit(0);
            }
            //run decryption
            dec(Base64.getDecoder().decode(args[1]), args[2], args[3]);
        }
        else{
            LOG.info("Invalid instruction type");
        }
    }

    /**
     * This method encrypts the file at the given path and saves at the location specified
     * @param key - the key used to encrypt the file
     * @param initVector - the initial vector for encrypting the file
     * @param inputDir - the path where the plaintext file is located
     * @param outputDir - the path where the encrypted file will be saved
     * @throws Exception - exceptions thrown by internal methods
     */
    public void enc(byte[] key, byte[] initVector, String inputDir, String outputDir) throws Exception {
        IvParameterSpec iv = new IvParameterSpec(initVector);
        SecretKeySpec secret = new SecretKeySpec(key, ALGORITHM);
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, secret, iv);
        try (InputStream fin = Files.newInputStream(Paths.get(inputDir));
             OutputStream fout = new FileOutputStream(outputDir);
             CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher) {
             }) {
            try {
                fout.write(initVector); //write the IV to the file
                final byte[] bytes = new byte[1024];
                for (int length = fin.read(bytes); length != -1; length = fin.read(bytes)) {
                    cipherOut.write(bytes, 0, length);
                }
            } catch (IOException e) {
                System.out.println(e.getMessage());
            }
        } catch (Exception e) {
            LOG.log(Level.INFO, "Unable to run encrpytion.");
        }
        LOG.info("Encryption finished, saved at " + outputDir);
    }

    /**
     * This method decrypts the file at the given path and saves the decrypted text to the location specified
     * @param key - the key used to encrypt the file
     * @param inputDir - the path to the encrypted file to be decrypted
     * @param outputDir - the path where the decrypted file will be saved
     * @throws Exception - exceptions thrown by internal methods
     */
    public void dec(byte[] key, String inputDir, String outputDir) throws Exception {
        byte[] ivs = new byte[16];
        try (InputStream encrypted = Files.newInputStream(Paths.get(inputDir))) {
            encrypted.read(ivs);
            IvParameterSpec iv = new IvParameterSpec(ivs);
            SecretKeySpec secret = new SecretKeySpec(key, ALGORITHM);
            Cipher cipher = Cipher.getInstance(CIPHER);
            cipher.init(Cipher.DECRYPT_MODE, secret, iv);

            try (CipherInputStream decryptStream = new CipherInputStream(encrypted, cipher);OutputStream decryptOut = new FileOutputStream(outputDir)){
                final byte[] bytes = new byte[1024];
                for (int length = decryptStream.read(bytes); length != -1; length = decryptStream.read(bytes)) {
                    decryptOut.write(bytes, 0, length);
                }
            } catch (IOException e) {
                System.out.println(e.getMessage());
            }
        } catch (IOException ex) {
            Logger.getLogger(FileEncryptor.class.getName()).log(Level.SEVERE, "Unable to decrypt", ex);
        }
        LOG.info("Decryption complete, open " + outputDir);
    }
}
