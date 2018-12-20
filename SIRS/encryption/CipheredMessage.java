package encryption;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;


public class CipheredMessage{

	private byte[] ciphered_bytes;
	private byte[] iv_bytes ;
	private char operation;
	



	public CipheredMessage(MessageAndHash mh, byte[] keyBytes, char op) throws Exception{

		operation = op;

		this.iv_bytes = new byte[16];
		SecureRandom rand = new SecureRandom();
		rand.nextBytes(iv_bytes);

		IvParameterSpec iv_spec = new IvParameterSpec(iv_bytes);
		SecretKeySpec key_spec = new SecretKeySpec(keyBytes, "AES");

		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, key_spec, iv_spec);


		byte[] mh_bytes = mh.toBytes();

		ciphered_bytes = cipher.doFinal(mh_bytes);

	}



	//USE THIS CONSTRUCTOR WHEN RECEIVING PACKETS FROM UDP
	public CipheredMessage( byte[] cmh_iv_bytes ){


		ByteBuffer bb = ByteBuffer.wrap(cmh_iv_bytes);
		operation = bb.getChar();
		ciphered_bytes = new byte[80];
		iv_bytes       = new byte[16];
		bb.get(ciphered_bytes);
		bb.get(iv_bytes);

	}


	// SEND THIS OVER UDP
	public byte[] toBytes(){

		ByteBuffer bb = ByteBuffer.allocate(2+iv_bytes.length + ciphered_bytes.length);

		bb.putChar(operation);
		bb.put(ciphered_bytes);
		bb.put(iv_bytes);

		return bb.array();

	}







	public MessageAndHash decipher(byte[] keybytes) throws Exception {


		IvParameterSpec iv_spec = new IvParameterSpec(iv_bytes);
		SecretKeySpec key_spec = new SecretKeySpec(keybytes, "AES");

		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, key_spec, iv_spec);


		byte[] mh_bytes  = cipher.doFinal(ciphered_bytes);

		return new MessageAndHash( mh_bytes );


	}




	public void print(){


		System.out.println("Operation "+ operation);
		System.out.println("Ciphered bytes" + new String(ciphered_bytes) );
		System.out.println("IV bytes" + new String(iv_bytes) );

	}


}