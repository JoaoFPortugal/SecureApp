package user;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.net.*;


public class User {

    String password;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private int phoneNumber;
    private UserManager userManager;
    DatagramSocket socket_client;
    DatagramSocket socket_sender;


    public User(UserManager userManager,int phoneNumber) {
        this.userManager = userManager;
        this.phoneNumber = phoneNumber;
    }


    public User(UserManager userManager, String password, int phoneNumber, byte[] privateKey, byte[] publicKey, DatagramSocket socket_client, DatagramSocket socket_sender){
        this.password = password;
        this.phoneNumber = phoneNumber;
        this.userManager = userManager;
        this.socket_client = socket_client;
        this.socket_sender = socket_sender;
        try {
            PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(privateKey);
            KeyFactory kf = KeyFactory.getInstance("EC");
            this.privateKey = kf.generatePrivate(ks);
        }catch(Exception e){
            e.printStackTrace();
        }

        try{
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
            KeyFactory kf = KeyFactory.getInstance("EC");
            this.publicKey = kf.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey(){
        return publicKey;
    }

    public int getPhoneNumber(){
        return phoneNumber;
    }

    public DatagramSocket getSocket_client() {
        return socket_client;
    }

    public DatagramSocket getSocket_sender() {
        return socket_sender;
    }
}
