package server;

public class ServerManager{

    public static void main(String[] args){
        Server server = new Server();
        Thread t1 = new Thread(server,"thread1");
        Thread t2 = new Thread(server,"thread2");
        t1.start();
        t2.start();
    }
}