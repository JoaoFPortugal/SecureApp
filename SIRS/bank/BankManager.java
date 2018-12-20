package bank;

public class BankManager{

    public static void main(String[] args){
        Bank bank = new Bank();
        Thread t1 = new Thread(bank,"thread1");
        Thread t2 = new Thread(bank,"thread2");
        t1.start();
        t2.start();
    }
}