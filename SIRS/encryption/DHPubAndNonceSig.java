package encryption;


import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

@SuppressWarnings("Duplicates")

public class DHPubAndNonceSig{

	int sequence_marker;
	int sig_len;
	byte[] sig_bytes;
	char op;


	public DHPubAndNonceSig(DHPubAndNonce pubAndNonce, PrivateKey signingKey, char op) throws Exception{

		sequence_marker = 2;
		this.op = op;

		Signature dsa = Signature.getInstance("SHA256withECDSA");
		dsa.initSign(signingKey);

		//Sign the dhpublic value and the nonce
		dsa.update(pubAndNonce.toBytes() );

		sig_bytes = dsa.sign();
		sig_len   = sig_bytes.length;

		//System.out.println( "Signatured length " + sig_bytes.length );

	}

	public DHPubAndNonceSig( DHPubAndNonce pubAndNonce, PrivateKey signingKey) throws Exception{

		this(pubAndNonce, signingKey, 'M');

	}


	public DHPubAndNonceSig( byte[] bytes ) throws Exception{

		ByteBuffer bb = ByteBuffer.wrap(bytes);
		op = bb.getChar();
		sequence_marker = bb.getInt();
		sig_len = bb.getInt();


		if(!(sig_len>0 && sig_len<100) ){
			throw new Exception("Invalid siglen "+ sig_len);
		}

		sig_bytes = new byte[sig_len];
		bb.get(sig_bytes);
	}


	public byte[] toBytes(){

		ByteBuffer bb = ByteBuffer.allocate(10 + sig_len);
		bb.putChar(op);
		bb.putInt(sequence_marker);
		bb.putInt(sig_len);
		bb.put(sig_bytes);

		return bb.array();

	}


	public boolean verify( DHPubAndNonce pubAndNonce, PublicKey verifyingKey ) throws Exception{

		Signature dsa = Signature.getInstance("SHA256withECDSA");

		dsa.initVerify( verifyingKey );
		dsa.update( pubAndNonce.toBytes() );

		return dsa.verify( sig_bytes );
	}

	public int getMarker(){
		return sequence_marker;
	}


	public void print(){
		System.out.println();
		System.out.println( "Signature bytes " + ECUtil.bytesToHex(sig_bytes) );
		System.out.println("Sig len" + sig_len);
		System.out.println();
	}


}