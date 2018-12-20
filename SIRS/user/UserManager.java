package user;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import static java.lang.System.exit;

public class UserManager implements java.io.Serializable {


    private static UserManager _usermanager;
    private String strongpassword;
    private boolean exit;
    private String password;
    public static int counter;


    public static UserManager getUserManager(){
        if(_usermanager==null){
            _usermanager = new UserManager();
        }

        return _usermanager;
    }


    public static void main(String[] args){
        counter = 0;



        UserManager userManager = getUserManager();
        User user;

        File f = new File("../res/counter.txt");
        if(f.exists()){
            FileInputStream file = null;
            try {
                file = new FileInputStream("../res/counter.txt");
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            }

            try {
                 _usermanager.counter = file.read();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        userManager.println("Please enter your phone number");
        String input = userManager.readString();
        if(input.length()!=9){
            userManager.println("Invalid number");
            exit(0);
        }
        int phoneNumber = 0;
        try{
            phoneNumber = Integer.parseInt(input);
        } catch(Exception e){
            e.printStackTrace();
        }

        boolean exists = userManager.verifyUser(phoneNumber);

        if(exists){
            userManager.println("\nWelcome Back!\n");
            user = userManager.loadUser(phoneNumber);
        }
        else{
            user = userManager.createNewUser(phoneNumber);
        }

        MainMenu menu = new MainMenu(_usermanager,user);
        menu.run();
    }

    private User createNewUser(int phoneNumber){

        CreateUser createUser = new CreateUser(phoneNumber,this);
        User user = createUser.create();
        _usermanager.counter++;
        try {
            FileOutputStream file = new FileOutputStream("../res/counter.txt");
            file.write(counter);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return user;

    }


    public byte[] fromHex(String hex)
    {
        byte[] bytes = new byte[hex.length() / 2];
        for(int i = 0; i<bytes.length ;i++)
        {
            bytes[i] = (byte)Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return bytes;
    }


    private User loadUser(int phoneNumber) {

        LoadUser loadUser = new LoadUser(phoneNumber,this);
        User user = loadUser.loadUser();
        return user;
    }


    private boolean verifyUser(int phoneNumber) {

        File f = new File("../res/" + phoneNumber + "file.txt");  //go to resources folder;
        if(!(f.exists() && !f.isDirectory())){
            return false;
        }

        else{
            return true;
        }
    }

    public void println(String str){
        System.out.println(str);
    }

    public String readString(){
        Console console = System.console();
        String input = console.readLine();
        return input;
    }

    public String readPassword(){
        Console console =  System.console();
        char [] input = console.readPassword("Please enter your secret password:  ");
        return String.valueOf(input);
    }

    public String readPassword(String str){
        Console console = System.console();
        char [] input = console.readPassword("Please reenter your secret password:  ");
        return String.valueOf(input);
    }

    public PublicKey getServerPubKey() {
        byte[] publicKey;
        try {
            FileInputStream file = new FileInputStream("../res/serverPublicKey.txt");
            publicKey = file.readAllBytes();
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
            KeyFactory kf = KeyFactory.getInstance("EC");
            return kf.generatePublic(keySpec);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
     return null;
    }
}
