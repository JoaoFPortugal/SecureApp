package encryption;

import java.nio.ByteBuffer;
import java.util.Date;

public class Message {


    private char operation;
    private int origin;
    private int destination;
    private long now;
    private float value;


    public Message(int origin, int destination, char operation, float value){
        this.origin = origin;
        this.destination = destination;
        this.operation = operation;
        this.value = value;
    }


    public Message(int origin, int destination, char operation, long now,float value){
        this.origin = origin;
        this.destination = destination;
        this.operation = operation;
        this.value = value;
        this.now = now;
    }


    public long createTimeStamp(){
        Date date = new Date();
        now = date.getTime();
        return now;
    }


    public int getOrigin(){
        return origin;
    }

    public int getDestination(){
        return destination;
    }

    public float getValue(){
        return value;
    }


    public void print(){

        System.out.println();
        System.out.println(this.operation);
        System.out.println(this.origin);
        System.out.println(this.destination);
        System.out.println(this.now);
        System.out.println(this.value);

        System.out.println();

    }




    public byte[] toBytes(){


        ByteBuffer bb = ByteBuffer.allocate(22);

        bb.putChar(operation);
        bb.putInt(origin);
        bb.putInt(destination);
        bb.putLong(now);
        bb.putFloat(value);


        return bb.array();



    }



    public static Message fromBytes(byte[] mbytes){


        ByteBuffer bb = ByteBuffer.wrap(mbytes);

        char  moperation = bb.getChar();
        int   morigin = bb.getInt();
        int   mdestination  = bb.getInt();
        Long  mnow = bb.getLong();
        Float mvalue = bb.getFloat();


    
        return new Message(morigin, mdestination, moperation, mnow, mvalue);


    }



}