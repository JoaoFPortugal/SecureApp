package user;

import encryption.HashMessage;
import encryption.StrongPasswordGenerator;
import encryption.SymmetricKeyEncryption;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.net.*;
import java.nio.ByteBuffer;

public class LoadUser {

    private int phoneNumber;
    private UserManager userManager;
    String strongpassword;

    public LoadUser(int phoneNumber, UserManager userManager) {

        this.phoneNumber = phoneNumber;
        this.userManager = userManager;
    }


    public User loadUser(){
        int counter=0;
        while(counter!=3){
            String password = userManager.readPassword();
            boolean left = invertPBKDF2(password,phoneNumber);
            if(left){
                byte[] originalKey = new byte[0];
                originalKey = loadKey(phoneNumber,userManager.fromHex(strongpassword));
                byte[] privateKey = loadPrivateKey(phoneNumber,originalKey);
                byte[] publicKey = loadPublicKey(phoneNumber);


                int socket_client_nr = loadSocketClient(phoneNumber);
                int socket_sender_nr = loadSocketSender(phoneNumber);

                DatagramSocket socket_client=null;
                DatagramSocket socket_sender=null;
                try {
                    InetAddress add = InetAddress.getByName("localhost");
                    socket_client = new DatagramSocket(socket_client_nr, add);
                    socket_sender = new DatagramSocket(socket_sender_nr, add);

                } catch (SocketException e) {
                    e.printStackTrace();
                } catch (UnknownHostException e) {
                    e.printStackTrace();
                }

                //System.out.println(new String(privateKey, Charset.defaultCharset()));
                return new User(userManager,password,phoneNumber, privateKey,publicKey, socket_client, socket_sender);
            }
            userManager.println("Wrong password please try again");
            userManager.println("you have  "+ (3-counter) + " tries left");
            counter++;
        }
        userManager.println("You entered your password too many times, please try again in 5 minutes");
        return null;

    }

    private int loadSocketClient(int phoneNumber){
        try{
            FileInputStream fis = new FileInputStream("../res/SocketClient" + phoneNumber + ".txt");
            ByteBuffer bb = ByteBuffer.wrap(fis.readAllBytes());
            return bb.getInt();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return 0;
    }
    private int loadSocketSender(int phoneNumber){
        try{
            FileInputStream fis = new FileInputStream("../res/SocketSender" + phoneNumber + ".txt");
            ByteBuffer bb = ByteBuffer.wrap(fis.readAllBytes());
            return bb.getInt();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return 0;
    }
    private byte[] loadPublicKey(int phoneNumber) {
        try{
            FileInputStream fis = new FileInputStream("../res/publicKey" + phoneNumber + ".txt");
            return fis.readAllBytes();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    private byte[] loadKey(int phoneNumber, byte[] password) {
        SymmetricKeyEncryption symmetricKeyEncryption1 = null;
        symmetricKeyEncryption1 = new SymmetricKeyEncryption(userManager.fromHex(strongpassword));
        try {
            FileInputStream fis = new FileInputStream("../res/EncryptedKey" + phoneNumber + "file.txt");
            byte[] ciphered = fis.readAllBytes();
            fis.close();
            return symmetricKeyEncryption1.decrypt(ciphered);

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    private byte[] loadPrivateKey(int phoneNumber,byte[] decryptedKey) {


        SymmetricKeyEncryption symmetricKeyEncryption = new SymmetricKeyEncryption(decryptedKey);

        byte[] decryptedPrivateKey = new byte[0];

        try {
            FileInputStream fis = new FileInputStream("../res/" + phoneNumber + "file.txt");
            byte[] privateKeyEncoded = fis.readAllBytes();
            fis.close();
            decryptedPrivateKey = symmetricKeyEncryption.decrypt(privateKeyEncoded);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return decryptedPrivateKey;
    }

    private boolean invertPBKDF2(String password,int phoneNumber) {
        //load salt
        byte[] salt = loadSalt(phoneNumber);

        String key = generatePassword(password,salt);


        String parts[] = key.split(":");

        //generate hash of key

        byte[] finalKey = new byte[0];
        finalKey = userManager.fromHex(parts[2]);

        HashMessage hashMessage = new HashMessage();
        byte[] hashedMessage = hashMessage.hashBytes(finalKey);

        //load hash from file

        byte[] hashedPassword = loadHash(phoneNumber);

        if(Arrays.equals(hashedMessage,hashedPassword)){
            strongpassword = parts[2];
            return true;
        }
        return false;
    }

    private String generatePassword(String password,byte[] salt) {
        StrongPasswordGenerator pass = new StrongPasswordGenerator(password);
        try {
            return pass.generateStrongPasswordHash(salt);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }

    private byte[] loadHash(int phoneNumber) {

        try {
            FileInputStream fis = new FileInputStream("../res/hashedPasswordfile" + phoneNumber + ".txt");
            return fis.readAllBytes();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    private byte[] loadSalt(int phoneNumber) {
        try{
            FileInputStream fis = new FileInputStream("../res/saltfile" + phoneNumber + ".txt");
            return fis.readAllBytes();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

}
