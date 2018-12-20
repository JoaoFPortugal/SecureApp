package encryption;

import encryption.Message;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.Arrays;


public class MessageAndHash {


	static MessageDigest md;

	byte[] hash;
	byte[] message;


	

	public MessageAndHash( Message m ) throws Exception{

		md = MessageDigest.getInstance("SHA-256");
		this.message = m.toBytes();
		this.hash = md.digest(message);

	}




	public MessageAndHash ( byte[] bytes ) {

		

		ByteBuffer bb = ByteBuffer.wrap(bytes);

		message = new byte[22];
		hash    = new byte[32];


		bb.get(message);
		bb.get(hash);

	}


	public Message getMessage(){
		Message m = Message.fromBytes(message);
		return m;
	}




	public boolean isValid() throws Exception{

		md = MessageDigest.getInstance("SHA-256");

		return Arrays.equals( md.digest(message), hash );

	}




	public byte[] toBytes(){

		ByteBuffer bb = ByteBuffer.allocate(64);

        bb.put(message);
        bb.put(hash);

        //System.out.println("tobytes len "+ bb.array().length);

        return bb.array();

	}



	public void print(){


		Message m = Message.fromBytes(message);
		m.print();
		System.out.println("Hash "+ new String(hash) );

	}

}