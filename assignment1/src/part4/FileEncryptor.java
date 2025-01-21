package com.packtpub.crypto.section5.src.part4;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.attribute.UserDefinedFileAttributeView;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * CYBR373 Assignment 1 Part 2
 * Cam Olssen (300492582)
 */
public class FileEncryptor {
    private static final Logger LOG = Logger.getLogger(FileEncryptor.class.getSimpleName());
    private static final SecureRandom RANDOM = new SecureRandom();
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
            e.printStackTrace();
        }
    }

    /**
     * This method runs the first step of the algorithm by reading the user's input
     * @param args - arguments passed from main
     * @throws Exception - for exception handling
     */
    public void run(String[] args) throws Exception {
        if (Objects.equals(args[0], "enc")) {
            if (args.length != 6) {
                LOG.info("Invalid number of arguments!");
                System.exit(0);
            }
            //default values
            String algorithm = "AES";
            int keylength = 128;

            if(Objects.equals(args[1], "AES")){
                try{
                    keylength = Integer.parseInt(args[2]);
                    if(!(keylength == 128 || keylength == 192 || keylength == 256)){
                        System.out.println("Invalid key length, must be 128, 192 or 256");
                        System.exit(0);
                    }
                } catch (NumberFormatException nfe){
                    System.out.println("Key length must be a number!");
                    System.exit(0);
                }
                algorithm = args[1];
            }
            else if(Objects.equals(args[1], "Blowfish")){
                try{
                    keylength = Integer.parseInt(args[2]);
                    if(!(keylength >= 32 && keylength <= 448)){
                        System.out.println("Invalid key length, must be between 32 and 448");
                        System.exit(0);
                    }
                } catch (NumberFormatException nfe){
                    System.out.println("Key length must be a number!");
                    System.exit(0);
                }
                algorithm = args[1];
            }
            else{
                System.out.println(args[1]+ " is an invalid algorithm. Please select Blowfish or AES.");
            }
            try{
                keylength = Integer.parseInt(args[2]);
            } catch (NumberFormatException nfe){
                System.out.println("Key length must be a number!");
                System.exit(0);
            }
            //run encryption
            enc(algorithm, keylength, args[3].toCharArray(), args[4], args[5]);
        } else if (Objects.equals(args[0], "dec")) {
            if (args.length != 4) {
                LOG.info("Invalid number of arguments!");
                System.exit(0);
            }
            //run decryption
            dec(args[1].toCharArray(), args[2], args[3]);
        } else if (Objects.equals(args[0], "info")) {
            info(args[1]);
        } else{
            LOG.info("Invalid instruction type");
        }
    }

    /**
     * This method encrypts the file at the given path and saves at the location specified
     * @param algorithm - algorithm used for encryption
     * @param keylength - length of the key
     * @param password - the user's password for encryption
     * @param inputDir - the path where the plaintext file is located
     * @param outputDir - the path where the encrypted file will be saved
     * @throws Exception - exceptions thrown by internal methods
     */
    public void enc(String algorithm, int keylength, char[] password, String inputDir, String outputDir) throws Exception {

        Cipher cipher = Cipher.getInstance(algorithm + "/CBC/PKCS5Padding");
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        byte[] initVector = new byte[cipher.getBlockSize()];
        RANDOM.nextBytes(initVector);

        IvParameterSpec iv = new IvParameterSpec(initVector);
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password, salt, 1000, keylength);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey pbeKey = keyFactory.generateSecret(pbeKeySpec);
        SecretKeySpec secret = new SecretKeySpec(pbeKey.getEncoded(), algorithm);

        cipher.init(Cipher.ENCRYPT_MODE, secret, iv);
        System.out.println("Secret key = "+new String((Base64.getEncoder().encode(secret.getEncoded()))));
        System.out.println("Algorithm = "+algorithm);
        System.out.println("Key length = "+keylength);
        try (InputStream fin = Files.newInputStream(Paths.get(inputDir));
             OutputStream fout = new FileOutputStream(outputDir);
             CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher) {
             }) {
            try {
                fout.write(initVector); //write the IV to the file
                fout.write(salt); //write the salt to the file

                final byte[] bytes = new byte[1024];
                for (int length = fin.read(bytes); length != -1; length = fin.read(bytes)) {
                    cipherOut.write(bytes, 0, length);
                }

                //write metadata to file
                UserDefinedFileAttributeView userDefinedFAView = Files.getFileAttributeView(Paths.get(outputDir), UserDefinedFileAttributeView.class);
                //write the key to the metadata
                userDefinedFAView.write(keylength+"", Charset.defaultCharset().encode(keylength+""));
                //write the algorithm to the metadata
                userDefinedFAView.write(algorithm, Charset.defaultCharset().encode(algorithm));
            } catch (IOException e) {
                System.out.println(e.getMessage());
                e.printStackTrace();
            }
        } catch (Exception e) {
            LOG.log(Level.INFO, "Unable to run encrpytion.");
            e.printStackTrace();
        }
        LOG.info("Encryption finished, saved at " + outputDir);
    }

    /**
     * This method decrypts the file at the given path and saves the decrypted text to the location specified
     * @param password - the user's password for encryption
     * @param inputDir - the path to the encrypted file to be decrypted
     * @param outputDir - the path where the decrypted file will be saved
     * @throws Exception - exceptions thrown by internal methods
     */
    public void dec(char[] password, String inputDir, String outputDir) throws Exception {
        byte[] salt = new byte[16];

        try (InputStream encrypted = Files.newInputStream(Paths.get(inputDir))) {
            List<String> attributes = getFileAttributes(inputDir);
            Cipher cipher = Cipher.getInstance(attributes.get(1) + "/CBC/PKCS5Padding");
            int ivlength = cipher.getBlockSize();
            byte[] ivs = new byte[ivlength];

            encrypted.read(ivs);
            encrypted.read(salt);
            IvParameterSpec iv = new IvParameterSpec(ivs);
            PBEKeySpec pbeKeySpec = new PBEKeySpec(password, salt, 1000, Integer.parseInt(attributes.get(0)));
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256AndAES_256");
            SecretKey pbeKey = keyFactory.generateSecret(pbeKeySpec);
            SecretKeySpec secret = new SecretKeySpec(pbeKey.getEncoded(), attributes.get(1));

            cipher.init(Cipher.DECRYPT_MODE, secret, iv);

            try (CipherInputStream decryptStream = new CipherInputStream(encrypted, cipher);OutputStream decryptOut = new FileOutputStream(outputDir)){
                final byte[] bytes = new byte[1024];
                for (int length = decryptStream.read(bytes); length != -1; length = decryptStream.read(bytes)) {
                    decryptOut.write(bytes, 0, length);
                }
            } catch (IOException e) {
                System.out.println(e.getMessage());
                e.printStackTrace();
            }
        } catch (IOException ex) {
            Logger.getLogger(FileEncryptor.class.getName()).log(Level.SEVERE, "Unable to decrypt", ex);
            ex.printStackTrace();
        }
        LOG.info("Decryption complete, open " + outputDir);
    }

    public void info(String inputDir){
        for(String attribute : getFileAttributes(inputDir)){
            System.out.println(attribute + " ");
        }
    }

    /**
     * @param inputDir - file that we want to read the metadata from
     * @return - a list of file attributes as strings
     */
    public List<String> getFileAttributes(String inputDir){
        List<String> attributes = new ArrayList<>();
        try {
            UserDefinedFileAttributeView fileAttributeView = Files.getFileAttributeView(Paths.get(inputDir), UserDefinedFileAttributeView.class);
            attributes = fileAttributeView.list();
        } catch (IOException e) {
            System.out.println("Error reading metadata " + e.getMessage());
            e.printStackTrace();
        }
        if(attributes.size() != 2){
            System.out.println("Incorrect number of attributes");
        }
        return attributes;
    }
}
