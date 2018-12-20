package encryption;

import java.nio.ByteBuffer;
import java.security.PublicKey;


public class DHPubAndNonce{


    PublicKey key;
    int nonce;
    int sequence_marker;
    char op;


    public DHPubAndNonce(PublicKey dhPub, int n, char op){

        this.op = op;
        key = dhPub;
        nonce = n;
        sequence_marker = 1;

    }

    public DHPubAndNonce(PublicKey dhPub, int n){

        this.op = op;
        key = dhPub;
        nonce = n;
        sequence_marker = 1;

    }


    public PublicKey getKey(){
        return key;
    }



    public DHPubAndNonce( byte[] packet_bytes ) throws Exception{

        ByteBuffer bb = ByteBuffer.wrap(packet_bytes);
        op = bb.getChar();
        sequence_marker = bb.getInt();
        nonce = bb.getInt();

        byte[] dhpub_bytes = new byte[80];
        bb.get(dhpub_bytes);

        key = ECUtil.loadPub(dhpub_bytes);

    }

    public byte[] toBytes(){
        ByteBuffer bb = ByteBuffer.allocate(86);
        bb.putChar(op);
        bb.putInt(sequence_marker);
        bb.putInt(nonce);
        bb.put( key.getEncoded() );

        return bb.array();
    }


    public void print(){

        System.out.println();
        System.out.println("Sequence marker" + sequence_marker );
        System.out.println("nonce "+ nonce);
        System.out.println( "DHpub " + ECUtil.keyToHex(key) );
        System.out.println();
    }

    public int getMarker(){
        return sequence_marker;
    }

    public int getNonce(){
        return nonce;
    }

}