package encryption;

import javax.crypto.KeyAgreement;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;


public class ECDH {

    PrivateKey privateKey;
    PublicKey publicKey;

    public ECDH(){

        KeyPairGenerator kpg = null;
        try {
            kpg = KeyPairGenerator.getInstance("EC");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        SecureRandom randomizer;
        try {
            randomizer = SecureRandom.getInstance("SHA1PRNG");
            kpg.initialize(224,randomizer);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        KeyPair kp = kpg.generateKeyPair();
        privateKey = kp.getPrivate();
        publicKey = kp.getPublic();
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public byte[] generateSharedSecret(PublicKey theirPub) throws InvalidKeyException, NoSuchAlgorithmException {

        // Perform key agreement
        KeyAgreement ka = null;
        try {
            ka = KeyAgreement.getInstance("ECDH");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        ka.init(privateKey);

        ka.doPhase(theirPub, true);

        // Read shared secret
        byte[] sharedSecret = ka.generateSecret();

        // Derive a key from the shared secret and both public keys
        MessageDigest hash = MessageDigest.getInstance("SHA-256");
        hash.update(sharedSecret);

        // Simple deterministic ordering
        List<ByteBuffer> keys = Arrays.asList(ByteBuffer.wrap(publicKey.getEncoded()), ByteBuffer.wrap(theirPub.getEncoded()));
        Collections.sort(keys);
        hash.update(keys.get(0));
        hash.update(keys.get(1));

        byte[] derivedKey = hash.digest();
        return derivedKey;
    }
}



