import javax.crypto.Cipher;
import java.math.BigInteger;
import java.net.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class EchoServer {

    private ServerSocket serverSocket;
    private Socket clientSocket;
    private DataOutputStream out;
    private DataInputStream in;

    /**
     * Create the server socket and wait for a connection.
     * Keep receiving messages until the input stream is closed by the client.
     *
     * @param port the port number of the server
     */
    public void start(int port, int keysize) {
        try {
            serverSocket = new ServerSocket(port);
            clientSocket = serverSocket.accept();
            out = new DataOutputStream(clientSocket.getOutputStream());
            in = new DataInputStream(clientSocket.getInputStream());
            Signature sign1 = Signature.getInstance("SHA256withRSA");
            byte[] data = new byte[512];
            int numBytes;

            //generate public & private keys, output public key to console
            final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(keysize);
            final KeyPair keyPair = kpg.generateKeyPair();
            final PublicKey publicKey = keyPair.getPublic();
            final PrivateKey privateKey = keyPair.getPrivate();
            System.out.println("Public key:");
            System.out.println(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
            RSAPublicKey pub = (RSAPublicKey) publicKey;
            BigInteger modulus = pub.getModulus();
            BigInteger exponent = pub.getPublicExponent();
            System.out.println("Public Key Modulus: "+modulus);
            System.out.println("Public Key ExponentL "+exponent);

            //Take destination public key as input and convert it to a PublicKey object
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            System.out.print("Destination public key: ");
            String destPK = reader.readLine();
            byte[] destPKBytes = Base64.getDecoder().decode(destPK);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey destinationPublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(destPKBytes));


            final String cipherName = "RSA/ECB/PKCS1Padding";
            Cipher cipher = Cipher.getInstance(cipherName);

            while ((numBytes = in.read(data)) != -1) {

                byte[] signature = new byte[256];
                byte[] message = new byte[256];
                ByteArrayInputStream inputStream = new ByteArrayInputStream(data);
                inputStream.read(signature);
                inputStream.read(message);

                //Decryption
                cipher.init(Cipher.DECRYPT_MODE, privateKey);
                byte[] decryptedBytes = cipher.doFinal(message);
                String decryptedString = new String(decryptedBytes, StandardCharsets.UTF_8);
                System.out.println("Received: "+ decryptedString);

                System.out.println("Checking signature.");
                sign1.initVerify(destinationPublicKey);
                sign1.update(decryptedBytes);
                if (sign1.verify(signature)) {
                    System.out.println("Signature matches!");
                } else {
                    throw new IllegalArgumentException("Signature does not match!");
                }


                //Encryption
                cipher.init(Cipher.ENCRYPT_MODE, destinationPublicKey);
                final byte[] originalBytes = decryptedString.getBytes(StandardCharsets.UTF_8);
                byte[] cipherTextBytes = cipher.doFinal(originalBytes);

                Signature sig = Signature.getInstance("SHA256withRSA");
                sig.initSign(privateKey);
                sig.update(originalBytes);
                byte[] signatureBytes = sig.sign();

                ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                outputStream.write(signatureBytes);
                outputStream.write(cipherTextBytes);

                System.out.println("Sent: "+ Util.bytesToHex(cipherTextBytes));
                out.write(outputStream.toByteArray());
                out.flush();
            }
            stop();
        } catch (IOException e) {
            System.out.println(e.getMessage());
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    /**
     * Close the streams and sockets.
     *
     */
    public void stop() {
        try {
            in.close();
            out.close();
            clientSocket.close();
            serverSocket.close();
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }

    }

    public static void main(String[] args) {
        EchoServer server = new EchoServer();
        int keysize = 2048;
        if(args.length >= 1){
            keysize = Integer.parseInt(args[1]);
        }
        if(keysize == 2048 || keysize == 1024 || keysize == 4096){
            server.start(4444, keysize);
        }
        else{
            System.out.println("Invalid keysize input!");
        }
    }
}



