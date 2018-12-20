package user;

import encryption.Message;
import encryption.MessageAndHash;

import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;

import static java.lang.System.exit;

public class Menu implements Runnable {

    private final UserManager _usermanager;
    private final User _user;
    private final Object lock = new Object();

    DatagramSocket socket_client;
    DatagramSocket socket_sender;

    private byte[] buf = new byte[120];
    boolean flag=true;
    private DHPubAndNonce dhN = null;
    private DHPubAndNonceSig dhsigN = null;
    private TreeSet<Integer> nonceMapN = new TreeSet<>();
    private byte[] genSecret;
    private byte[] balanceKey;
    private DHPubAndNonce dh = null;
    private DHPubAndNonceSig dhsig = null;
    private TreeSet<Integer> nonceMap = new TreeSet<>();



    public Menu(UserManager userManager, User user){
        _usermanager = userManager;
        _user = user;
        socket_sender = user.getSocket_sender();
        socket_client = user.getSocket_client();

    }

    @Override
    public void run(){
        while(true){
            if(Thread.currentThread().getName().equals("thread1")){
                runreceiver();
            }
            else{
                runsender();
            }
        }
    }


    private void runreceiver() {
        DatagramPacket packet = new DatagramPacket(buf, buf.length);
        try {

            socket_client.receive(packet);
            debunkPacket(packet);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void debunkPacket(DatagramPacket packet){
        int port = packet.getPort();
        if(port!=4440){
            return;
        }
        char op = retrieveOp(packet);
        switch(op){

            case 'R':
                checkPacket(packet);
                break;

            case 'N':
                checkPacketTwice(packet);
                break;

            case 'M':

                CipheredMessage message = new CipheredMessage(packet.getData());
                try {
                    MessageAndHash mh = message.decipher(genSecret);
                    if(mh.isValid()){
                        Message m = mh.getMessage();
                        double d = m.getValue();
                        System.out.println("you just received " + d + " euros from " + m.getOrigin() + "!!!");
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
                break;

            case 'L':
                CipheredMessage balanceMessage = new CipheredMessage(balanceKey);
                try {
                    MessageAndHash mh = balanceMessage.decipher(packet.getData());
                    if(mh.isValid()){
                        Message m = mh.getMessage();
                        System.out.println("you just have " + m.getValue() + " euros");
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }


            default:
                break;
        }

    }



    private void checkPacketTwice(DatagramPacket packet) {
        int i = getSequenceMarker(packet);
        if(i==1){
            try {
                DHPubAndNonce dHPubAndNonce = new DHPubAndNonce(packet.getData());
                dhN = dHPubAndNonce;
                int nonce = dhN.getNonce();

                if(nonceMapN!=null) {

                    if (nonceMapN.contains(nonce)) {
                        dhN = null;
                        return;
                    } else {
                        nonceMapN.add(nonce);
                    }
                }

                else{
                    nonceMapN.add(nonce);
                }

            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        else if(i==2){
            DHPubAndNonceSig dHPubAndNonceSig;
            try {
                dHPubAndNonceSig = new DHPubAndNonceSig(packet.getData());
                dhsigN = dHPubAndNonceSig;
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        if(dhN!=null && dhsigN!=null) {
            try {
                boolean verify = dhsigN.verify(dhN, _usermanager.getServerPubKey());
                if(verify){
                    ECDH ephemeralKeys = new ECDH();
                    sendDH(ephemeralKeys,'R');
                    genSecret = ECUtil.genSharedSecret(ephemeralKeys.getPrivateKey(),dhN.getKey(),ephemeralKeys.getPublicKey());
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private char retrieveOp(DatagramPacket packet) {
        ByteBuffer buf = ByteBuffer.wrap(packet.getData());
        return buf.getChar();
    }



    private void checkPacket(DatagramPacket packet) {
        int i = getSequenceMarker(packet);

        if(i==1){
            try {
                DHPubAndNonce dHPubAndNonce = new DHPubAndNonce(packet.getData());
                dh = dHPubAndNonce;
                int nonce = dh.getNonce();
                if(nonceMap.contains(nonce)){
                    dh = null;
                    return;
                }
                else{
                    nonceMap.add(nonce);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        else if(i==2){
            DHPubAndNonceSig dHPubAndNonceSig;
            try {
                dHPubAndNonceSig = new DHPubAndNonceSig(packet.getData());
                dhsig = dHPubAndNonceSig;
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        if(dh!=null && dhsig!=null) {
            try {
                boolean verify = dhsig.verify(dh, _usermanager.getServerPubKey());
                if(verify){
                    synchronized (lock) {

                        flag = false;
                        lock.notifyAll();
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private int getSequenceMarker(DatagramPacket packet) {
        byte[] dataPacket = packet.getData();
        ByteBuffer bb = ByteBuffer.wrap(dataPacket);
        char op = bb.getChar();
        int sequenceMarker = bb.getInt();
        return sequenceMarker;
    }


    //implement client menu here
    private void runsender() {
        int option=0;
        _usermanager.println("What would you like to do?");
        _usermanager.println("1- Transfer Funds to Another user");
        _usermanager.println("2- Request Credit");
        _usermanager.println("3- Get Balance");
        _usermanager.println("4- Exit");
        String input = _usermanager.readString();
        try{
            option = Integer.parseInt(input);
        }
        catch(Exception e){
            _usermanager.println("Wrong input!");
        }
        
        switch(option){
            case 1:
                sendFunds();
                break;
            case 2:
                requestCredit();
                break;
            case 3:
                checkBalance();
                break;

            case 4:
                exit(0);

            default:
                _usermanager.println(("Wrong number!"));

        }
        
    }



    private void checkBalance(){

        ECDH ephemeralKeys = new ECDH();

        sendDH(ephemeralKeys,'B');


        //Sets a timer, if the lock object isn't notified in 45 seconds a TimeOutException is good
        //Makes program respond to an eventual packet loss.

        ExecutorService service = Executors.newSingleThreadExecutor();

        try{
            Runnable r = () -> {
                synchronized (lock){
                    while(flag == true){
                        try {
                            lock.wait();
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        }
                    }
                }
            };
            Future<?> f = service.submit(r);

            f.get(45, TimeUnit.SECONDS);
        }
        catch(final TimeoutException e){
            System.out.println("Sorry, a problem has occurred, please try again later..");
            return;
        }

        catch(Exception e){
            e.printStackTrace();
        }

        flag = true;

        try {
            balanceKey = ephemeralKeys.generateSharedSecret(dh.getKey());
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    private void requestCredit() {

        float value = askValue();

        if(value==-1){
            return;
        }

        //String message = _user.getPhoneNumber() + "-" + value;
        //byte[] msg = message.getBytes();

        try {
            InetAddress IPAddress = InetAddress.getByName("localhost");

            ByteBuffer bb = ByteBuffer.allocate(90);
            bb.putChar('B');
            bb.putInt(_user.getPhoneNumber());
            bb.putFloat( value );


            DatagramPacket sendPacket = new DatagramPacket(bb.array(), bb.array().length, IPAddress, 4446);

            socket_sender.send(sendPacket);

        }catch(Exception e){
            e.printStackTrace();
        }
    }



    private void sendFunds() {

        int destination = askPhoneNumber();
        if(destination==-1){
            return;
        }

        float value = askValue();

        if(value==-1){
            return;
        }
        
        
        ECDH ephemeralKeys = new ECDH();

        sendDH(ephemeralKeys,'N');
        
        
        //Sets a timer, if the lock object isn't notified in 45 seconds a TimeOutException is good
        //Makes program respond to an eventual packet loss.

        ExecutorService service = Executors.newSingleThreadExecutor();

        try{
            Runnable r = () -> {
                synchronized (lock){
                    while(flag == true){
                        try {
                            lock.wait();
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        }
                    }
                }
            };
            Future<?> f = service.submit(r);

            f.get(45, TimeUnit.SECONDS);
        }
        catch(final TimeoutException e){
            System.out.println("Sorry, a problem has occurred, please try again later..");
            return;
        }

        catch(Exception e){
            e.printStackTrace();
        }


        flag = true;

        byte[] key = new byte[0];
        
        try {
            key = ephemeralKeys.generateSharedSecret(dh.getKey());
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }


        byte[] cm_bytes;
        try{
            Message message = new Message(_user.getPhoneNumber(),destination,'T',value);
            MessageAndHash mh= new MessageAndHash(message);
            //encryption of the mh
            CipheredMessage cm = new CipheredMessage(mh, key);
            cm_bytes = cm.toBytes();
        }
        catch(Exception e){
            cm_bytes = new byte[0];
        }

        sendMessage( cm_bytes );

    }

    private void sendDH(ECDH ephemeralKeys,char op) {
        InetAddress ip = null;

        try {
             ip = InetAddress.getByName("localhost");
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }

        Random random = new Random();
        DHPubAndNonce firstPacket = new DHPubAndNonce(ephemeralKeys.getPublicKey(),random.nextInt(),op);
        DHPubAndNonceSig secondPacket = null;
        try {
            secondPacket = new DHPubAndNonceSig(firstPacket,_user.getPrivateKey(),op);
        } catch (Exception e) {
            e.printStackTrace();
        }

        byte[] firstpacket = firstPacket.toBytes();
        byte[] secondpacket = secondPacket.toBytes();


        DatagramPacket packet = new DatagramPacket(firstpacket,firstpacket.length,ip,4445);
        try {
            socket_sender.send(packet);
        } catch (IOException e) {
            e.printStackTrace();
        }
        try {
            Thread.sleep(100);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        DatagramPacket packet2 = new DatagramPacket(secondpacket,secondpacket.length,ip,4445);
        try {
            socket_sender.send(packet2);
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    private int askPhoneNumber() {

        _usermanager.println("Please enter the destination:  ");
        String input = _usermanager.readString();
        if(!input.matches("[0-9]*")){
            _usermanager.println("Please enter a valid phone number");
            return -1;
        }
        if(input.length()!=9){
            _usermanager.println("Please enter a valid number");
            return -1;
        }
        int destination=0;

        try{
            destination = Integer.parseInt(input);
        } catch (NumberFormatException e) {
            e.printStackTrace();
        }
        return destination;

    }

    private float askValue() {

        float value=0;

        _usermanager.println("Please enter the value of the transfer");

        String input = _usermanager.readString();
        if(!input.matches("([0-9]{0,3}[.][0-9]{1,2}|[0-9]{1,3})")){
            _usermanager.println("Please enter a valid transfer value");
            return -1;
        }

        try{
            value = Float.parseFloat(input);
        } catch (NumberFormatException e) {
            e.printStackTrace();
        }
        return value;

    }





    private void sendMessage(byte[] fullmessage) {
        InetAddress ip = null;

        try {
            ip = InetAddress.getByName("localhost");
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        DatagramPacket packet = new DatagramPacket(fullmessage,fullmessage.length,ip,4445);
        try {
            socket_sender.send(packet);
        } catch (IOException e) {
            e.printStackTrace();
        }

    }
}
