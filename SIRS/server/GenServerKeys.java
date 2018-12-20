package server;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.io.FileOutputStream;
import java.security.NoSuchAlgorithmException;


public class GenServerKeys{
	
	public GenServerKeys(){

	}



	public KeyPair gen_keys() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(224);
        KeyPair keys = keyGen.generateKeyPair();
        return keys;
    }

    public PrivateKey get_private_key(KeyPair keys) {
        PrivateKey privKey = keys.getPrivate();
        return privKey;
    }

    public PublicKey get_public_key(KeyPair keys){
        PublicKey pubKey = keys.getPublic();
        return pubKey;
    }


    public static void main(String[] args){
    	try{
	    	GenServerKeys generator = new GenServerKeys();
	    	KeyPair keypair = generator.gen_keys();

	    	PrivateKey privateKey = generator.get_private_key(keypair);
	    	byte[] privKey = privateKey.getEncoded();
	    	PublicKey publicKey = generator.get_public_key(keypair);
	    	byte[] pubKey = publicKey.getEncoded();


	    	FileOutputStream f = new FileOutputStream("../res/" + "serverPrivateKey.txt");
	        f.write(privKey);
	        FileOutputStream f2 = new FileOutputStream("../res/" + "serverPublicKey.txt");
	        f2.write(pubKey);
   		}catch(Exception e){e.printStackTrace();}
    }
}