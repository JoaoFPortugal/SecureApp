package certificado;

public class CertManager{


    public static void main(String[] args){
        Certificado certificado = new Certificado();
        Thread t1 = new Thread(certificado,"thread1");
        Thread t2 = new Thread(certificado,"thread2");
        t1.start();
        t2.start();
    }
}

