import java.io.*;
import java.math.BigInteger;
import java.net.*;
import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class EchoClient {

    private Socket clientSocket;
    private DataOutputStream out;
    private DataInputStream in;

    /**
     * Setup the two way streams.
     *
     * @param ip the address of the server
     * @param port port used by the server
     *
     */
    public void startConnection(String ip, int port) {
        try {
            clientSocket = new Socket(ip, port);
            out = new DataOutputStream(clientSocket.getOutputStream());
            in = new DataInputStream(clientSocket.getInputStream());
        } catch (IOException e) {
            System.out.println("Error when initializing connection");
        }
    }

    /**
     * Send a message to server and receive a reply.
     *
     * @param msg the message to send
     */
    public byte[] sendMessage(byte[] msg) {
        try {
            out.write(msg);
            out.flush();

            byte[] reply = new byte[512];
            in.read(reply);
            return reply;
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return null;
        }
    }

    /**
     * Close down our streams.
     *
     */
    public void stopConnection() {
        try {
            in.close();
            out.close();
            clientSocket.close();
        } catch (IOException e) {
            System.out.println("error when closing");
        }
    }

    public static void main(String[] args) throws IOException {
        EchoClient client = new EchoClient();
        BufferedReader read = new BufferedReader(new InputStreamReader(System.in));
        System.out.print("Input message: ");
        String message = read.readLine();
        int keysize = 2048;
        if(args.length >= 1){
            keysize = Integer.parseInt(args[0]);
        }
        if(keysize == 2048 || keysize == 1024 || keysize == 4096){
            client.run("127.0.0.1", 4444, message, keysize);
            client.stopConnection();
        }
        else{
            System.out.println("Invalid keysize input!");
        }
    }

    public void run(String ip, int port, String input, int keysize){
        try {
            final String message = input;
            startConnection(ip, port);

            //generate public & private keys, output public key to console
            final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(keysize);
            final KeyPair keyPair = kpg.generateKeyPair();
            final PublicKey publicKey = keyPair.getPublic();
            final PrivateKey privateKey = keyPair.getPrivate();;
            System.out.println("Public Key:");
            System.out.println(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
            RSAPublicKey pub = (RSAPublicKey) publicKey;
            BigInteger modulus = pub.getModulus();
            BigInteger exponent = pub.getPublicExponent();
            System.out.println("Public Key Modulus: "+modulus);
            System.out.println("Public Key Exponent: "+exponent);

            //Take destination public key as input and convert it to a PublicKey object
            BufferedReader read = new BufferedReader(new InputStreamReader(System.in));
            System.out.println("Destination public key: ");
            String destPK = read.readLine();
            byte[] destPKByte = Base64.getDecoder().decode(destPK);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey destinationPublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(destPKByte));

            //Encryption

            //Encrypt and sign message.
            final String cipherName = "RSA/ECB/PKCS1Padding";
            Cipher cipher = Cipher.getInstance(cipherName);
            cipher.init(Cipher.ENCRYPT_MODE, destinationPublicKey);

            //convert message to bytes
            final byte[] original = message.getBytes(StandardCharsets.UTF_8);
            byte[] ciphertextbytes = cipher.doFinal(original);
            Signature sign = Signature.getInstance("SHA256withRSA");
            sign.initSign(privateKey);
            sign.update(original);
            byte[] signaturebytes = sign.sign();
            String output = Util.bytesToHex(ciphertextbytes);
            System.out.println("Sent " + output);

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(signaturebytes);
            outputStream.write(ciphertextbytes);

            byte[] reply = sendMessage(outputStream.toByteArray());

            //Decryption
            byte[] signature = new byte[256];
            byte[] received = new byte[256];
            ByteArrayInputStream inputStream = new ByteArrayInputStream(reply);
            inputStream.read(signature);
            inputStream.read(received);

            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedBytes = cipher.doFinal(received);
            String decrypted = new String(decryptedBytes, StandardCharsets.UTF_8);
            System.out.println("Received: "+decrypted);

            System.out.println("Checking signature");
            sign.initVerify(destinationPublicKey);
            sign.update(decryptedBytes);

            if(sign.verify(signature)){
                System.out.println("Signature matches!");
            }
            else{
                throw new IllegalArgumentException("Signature does not match!");
            }
            stopConnection();
        }
        catch(Exception e){
            e.printStackTrace();
        }
    }
}
