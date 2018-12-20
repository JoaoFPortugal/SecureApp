package user;

import encryption.HashMessage;
import encryption.StrongPasswordGenerator;
import encryption.SymmetricKeyEncryption;

import java.io.File;
import java.io.FileOutputStream;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.net.*;
import java.nio.ByteBuffer;

import static java.lang.System.exit;

public class CreateUser {
    private int phoneNumber;
    private UserManager userManager;
    boolean exit;
    String password;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    DatagramSocket socket_client;
    DatagramSocket socket_sender;


    public CreateUser(int phoneNumber, UserManager userManager) {
        this.phoneNumber = phoneNumber;
        this.userManager = userManager;
    }


    public User create() {

        askForInput();
        if(exit==true){
            exit(0);
        }
        byte[] privKey=null;
        try{
            KeyPair keypair = gen_keys();
            privateKey = get_private_key(keypair);
            publicKey = get_public_key(keypair);
            privKey = privateKey.getEncoded();
        }catch(Exception e){e.printStackTrace();}

        storePublicKey(publicKey.getEncoded(), phoneNumber);
        encryptFiles(phoneNumber, privateKey);


        storeSockets(phoneNumber);
        sharePublicKey(publicKey,phoneNumber);
        return new User(userManager,password,phoneNumber,privKey,publicKey.getEncoded(), socket_client, socket_sender);
    }

    private void storePublicKey(byte[] encoded,int phoneNumber) {
        try {
            FileOutputStream fos = new FileOutputStream("../res/publicKey" + phoneNumber + ".txt");
            fos.write(encoded);
            fos.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void storeSockets(int phoneNumber){
        try {
            InetAddress add = InetAddress.getByName("localhost");
            socket_client = new DatagramSocket( 4447 + userManager.counter,add);
            socket_sender = new DatagramSocket(3447+userManager.counter,add);

        } catch (SocketException e) {
            e.printStackTrace();
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }

        try{
            ByteBuffer bb = ByteBuffer.allocate(4);
            bb.putInt(4447 + userManager.counter);
            ByteBuffer bb2 = ByteBuffer.allocate(4);
            bb2.putInt(3447 + userManager.counter);

            FileOutputStream fos = new FileOutputStream("../res/SocketClient" + phoneNumber + ".txt");
            fos.write(bb.array());
            fos.close();
            FileOutputStream fos2 = new FileOutputStream("../res/SocketSender" + phoneNumber + ".txt");
            fos2.write(bb2.array());
            fos2.close();

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    private void encryptFiles(int phoneNumber, PrivateKey privateKey) {

        //byte[] privKey = privateKey.getEncoded();


        SecureRandom random = new SecureRandom();
        byte[] key = new byte[16]; // 128 bits are converted to 16 bytes;
        random.nextBytes(key);

        encryptPrivateKey(key,phoneNumber, privateKey);

        StrongPasswordGenerator strongPasswordGenerator = new StrongPasswordGenerator(password);
        String strongPassword = null;
        try {
            strongPassword = strongPasswordGenerator.generateStrongPasswordHash();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        String[] parts = strongPassword.split(":");
        storeSalt(userManager.fromHex(parts[1]),phoneNumber);
        encryptKey(key,userManager.fromHex(parts[2]),phoneNumber);

        //finally create the hash of the PBKDF2 to check for integrity

        hashPassword(phoneNumber,userManager.fromHex(parts[2]));

    }


    private void storeSalt(byte[] salt,int phoneNumber) {
        try {
            FileOutputStream fos = new FileOutputStream("../res/saltfile" + phoneNumber + ".txt");
            fos.write(salt);
            fos.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    private void encryptPrivateKey(byte[] key, int phoneNumber, PrivateKey privateKey ) {

        SymmetricKeyEncryption symmetricKeyEncryption = new SymmetricKeyEncryption(key);
        try {

            File privateKeyFile = new File("../res/" + phoneNumber + "file.txt");
            privateKeyFile.createNewFile();
            //String encryptingThis = "Ola";
            //byte[] encryptedMessage = symmetricKeyEncryption.encrypt(encryptingThis.getBytes(Charset.defaultCharset()));
            byte[] encryptedMessage = symmetricKeyEncryption.encrypt(privateKey.getEncoded());
            FileOutputStream fos = new FileOutputStream("../res/" + phoneNumber + "file.txt");
            fos.write(encryptedMessage);
            fos.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    private void encryptKey(byte[] key, byte[] password, int phoneNumber) {

        try {
            SymmetricKeyEncryption symmetricKeyEncryption = new SymmetricKeyEncryption(password);
            byte[] encryptedKey = symmetricKeyEncryption.encrypt(key);
            FileOutputStream fos = new FileOutputStream("../res/EncryptedKey" + phoneNumber + "file.txt");
            fos.write(encryptedKey);
            fos.close();

        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void hashPassword(int phoneNumber, byte[] password) {
        HashMessage hashMessage = new HashMessage();

        byte[] hashedMessage = hashMessage.hashBytes(password);

        try {
            FileOutputStream fos = new FileOutputStream("../res/hashedPasswordfile" + phoneNumber + ".txt");
            fos.write(hashedMessage);
            fos.close();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    private void sharePublicKey(PublicKey publicKey,int phoneNumber){
        try {

            ByteBuffer bb = ByteBuffer.allocate(90);
            bb.putChar('C');
            bb.putInt(phoneNumber);
            bb.put( publicKey.getEncoded() );


            InetAddress IPAddress = InetAddress.getByName("localhost");

            DatagramPacket sendPacket = new DatagramPacket(bb.array(), bb.array().length, IPAddress, 4444);

            socket_sender.send(sendPacket);


        }catch(Exception e){
            e.printStackTrace();
        }
    }


    private KeyPair gen_keys() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");

        keyGen.initialize(224,random);
        KeyPair keys = keyGen.generateKeyPair();
        return keys;
    }

    private PrivateKey get_private_key(KeyPair keys) {
        PrivateKey privKey = keys.getPrivate();
        return privKey;
    }

    private PublicKey get_public_key(KeyPair keys){
        PublicKey pubKey = keys.getPublic();
        return pubKey;
    }

    private boolean verifyPassword(String password) {

        if (password.length() < 8) {
            return false;
        } else if (!password.matches(".*[A-Z].*")) {  // see if it has a capital letter
            return false;
        } else if (!password.matches(".*[a-z].*")) {
            return false;
        } else if (!password.matches(".*[0-9].*")) {
            return false;
        } else return !password.matches("[a-zA-Z0-9]*");  //if it doesnt have a special character return false
        //otherwise true
    }

    private String askForPassword() {
        password = userManager.readPassword();
        return password;
    }
    private String askForRepassword(){
        String repassword = userManager.readPassword("re");
        return repassword;
    }

    public void askForInput(){
        userManager.println("Welcome to our service, thank you for choosing us");
        while (true) {
            System.out.println("Press 1 to exit");
            String password = askForPassword();
            if(password.equals("1")){
                exit(0);
            }
            String repassword = askForRepassword();
            if (password.equals(repassword)) {
                if (verifyPassword(password)) {
                    break;
                } else {
                    userManager.println("\n\nThe password criteria did not match. Please make sure it is a password\n" +
                            "with at least 8 characters and has a capital letter, a lowercase letter" +
                            " a number and a special character.\n\n");
                    continue;
                }
            } else if (repassword.equals("1")) {
                exit(0);
            } else {
                userManager.println("\nPlease make sure both passwords match\n\n");
            }
        }

    }



}
