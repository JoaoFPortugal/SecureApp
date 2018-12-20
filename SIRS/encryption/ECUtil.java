package encryption;

import javax.crypto.KeyAgreement;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;


public class ECUtil {


	public ECUtil(){
	}



	public static PrivateKey loadPriv(byte[] priv_bytes) throws Exception{

        KeyFactory kf = KeyFactory.getInstance("EC");
        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(priv_bytes);
        PrivateKey priv_key = kf.generatePrivate(privSpec);
        return priv_key;

    }

    public static PublicKey loadPub(byte[] pub_bytes) throws Exception{

        KeyFactory kf = KeyFactory.getInstance("EC");
        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pub_bytes);

        PublicKey pub_key = kf.generatePublic(pubSpec);
        return pub_key;
    }


	public static PublicKey loadPub(String filename) throws Exception{

        byte[] pub_bytes = new FileInputStream(filename).readAllBytes();
        return loadPub(pub_bytes);

    }


    public static PrivateKey loadPriv(String filename) throws Exception{

        byte[] priv_bytes = new FileInputStream(filename).readAllBytes();
        return loadPriv(priv_bytes);

    }


    public static void generateToFiles( String pubfilename, String privfilename) throws Exception{


      KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
      kpg.initialize(224);
      KeyPair kp = kpg.generateKeyPair();
      byte[] ourPub = kp.getPublic().getEncoded();
      byte[] ourPriv = kp.getPrivate().getEncoded();


      FileOutputStream out = new FileOutputStream(pubfilename);
      out.write(ourPub);

      out = new FileOutputStream(privfilename);
      out.write(ourPriv);


    }


    public static String bytesToHex(byte[] bytes){

    	String    HEXES    = "0123456789ABCDEF";
    	StringBuilder hex = new StringBuilder(2 * bytes.length);

    	for (byte b : bytes) {
        	hex.append(HEXES.charAt((b & 0xF0) >> 4)).append(HEXES.charAt((b & 0x0F)));
    	}

    	return hex.toString();

    }

    

    public static String keyToHex( Key key){

    	byte[] key_bytes = key.getEncoded();
    	return bytesToHex(key_bytes);

    }



    public static byte[] genSharedSecret( PrivateKey ourPriv, PublicKey theirPub,PublicKey ourPub) throws Exception{


		KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(ourPriv);

        ka.doPhase(theirPub, true);

        byte[] sharedSecret = ka.generateSecret();

        MessageDigest hash = MessageDigest.getInstance("SHA-256");
        hash.update(sharedSecret);

        // Simple deterministic ordering
        List<ByteBuffer> keys = Arrays.asList(ByteBuffer.wrap(ourPub.getEncoded()), ByteBuffer.wrap(theirPub.getEncoded()));
        Collections.sort(keys);
        hash.update(keys.get(0));
        hash.update(keys.get(1));

        byte[] derivedKey = hash.digest();

        return derivedKey;

    }


}