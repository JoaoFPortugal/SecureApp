package encryption;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashMessage {

    public byte[] hashMessage(String message){
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        byte[] hashedMessage = digest.digest(message.getBytes(StandardCharsets.UTF_8));
        return hashedMessage;
    }

    public byte[] hashBytes(byte[] bytes){
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        byte[] hashedMessage = digest.digest(bytes);
        return hashedMessage;
    }
}
