package certificado;

import java.io.IOException;
import java.net.*;
import java.security.spec.X509EncodedKeySpec;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.nio.ByteBuffer;
import java.util.Stack;


public class Certificado implements Runnable{
    Stack<byte[]> stack;
    DatagramSocket socket;
    Stack<Integer> ports;


    public Certificado(){
        stack = new Stack();
        ports = new Stack();
        try {
            socket = new DatagramSocket( 4444);
        } catch (SocketException e) {
            e.printStackTrace();
        }
    }

    private void runreceiver() {
        byte[] buf = new byte[840];
        DatagramPacket packet = new DatagramPacket(buf, buf.length);

        try {
            socket.receive(packet);
            System.out.println("Received a message!");

            stack.push(packet.getData());
            ports.push(packet.getPort()+2000);

            ByteBuffer bb = ByteBuffer.wrap(packet.getData());

            char op = bb.getChar();
            System.out.println(op);

            int phoneNr = bb.getInt();
            System.out.println(phoneNr);

            byte[] pubKey = new byte[80];
            bb.get(pubKey);

            X509EncodedKeySpec ks = new X509EncodedKeySpec(pubKey);
            KeyFactory kf = KeyFactory.getInstance("EC");
            PublicKey publicKey = kf.generatePublic(ks);
            System.out.println(publicKey);



        } catch (Exception e) {
            e.printStackTrace();
        }
         
        
        
    }

    private void runsender() {
        if (!stack.empty()) {
            if (!ports.empty()) {
                byte[] message = stack.pop();
                int port = ports.pop();
                try {
                    System.out.println(port);
                    DatagramSocket socket_client = new DatagramSocket(port);
                    InetAddress IPAddress = InetAddress.getByName("localhost");


                    DatagramPacket sendPacket = new DatagramPacket(message, message.length, IPAddress, 4445);


                    socket_client.send(sendPacket);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }

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

}