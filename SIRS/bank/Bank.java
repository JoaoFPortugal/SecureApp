package bank;


import java.net.*;
import java.util.Arrays;
import java.util.Stack;
import java.nio.ByteBuffer;
import java.util.HashMap;

public class Bank implements Runnable{


    private DatagramSocket socket;
    Stack<byte[]> stack;
    Stack<Integer> ports;
    private HashMap<Integer,DatagramSocket> socket_senders;




    public Bank(){
        stack = new Stack();
        ports = new Stack();
        socket_senders = new HashMap<Integer,DatagramSocket>();
        try {
            socket = new DatagramSocket( 4446);
        } catch (SocketException e) {
            e.printStackTrace();
        }
    }


    private void runreceiver(){

        byte[] buf = new byte[840];
        DatagramPacket packet = new DatagramPacket(buf, buf.length);

        try{

            //receive
            socket.receive(packet);

            ports.push(packet.getPort()+3000);

            byte[] message = packet.getData();
            stack.push(message);

            ByteBuffer bb = ByteBuffer.wrap(packet.getData());

            char op = bb.getChar();
            System.out.println(op);

            int phoneNr = bb.getInt();
            System.out.println(phoneNr);

            Float val = bb.getFloat();
            System.out.println(val);




        }catch(Exception e){
            e.printStackTrace();
        }
    }

    private void runsender(){
        if (!stack.empty()) {
            if (!ports.empty()) {
                int port = ports.pop();
                byte[] message = stack.pop();
                try {
                    if(socket_senders.containsKey(port)){

                        DatagramSocket socket_sender=socket_senders.get(port);
                        InetAddress IPAddress = InetAddress.getByName("localhost");

                        DatagramPacket sendPacket = new DatagramPacket(message, message.length, IPAddress, 4445);
                        socket_sender.send(sendPacket);
                    }
                    else {
                        DatagramSocket socket_sender = new DatagramSocket(port);
                        socket_senders.put(port,socket_sender);
                        InetAddress IPAddress = InetAddress.getByName("localhost");

                        DatagramPacket sendPacket = new DatagramPacket(message, message.length, IPAddress, 4445);
                        socket_sender.send(sendPacket);
                    }
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