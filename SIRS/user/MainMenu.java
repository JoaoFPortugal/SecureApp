package user;

public class MainMenu {

    private final UserManager userManager;
    private final User user;

    public MainMenu(UserManager userManager,User user){
        this.userManager = userManager;
        this.user = user;
    }

    public void run(){
        Menu menu = new Menu(userManager,user);
        Thread t1 = new Thread(menu,"thread1");
        Thread t2 = new Thread(menu,"thread2");
        t1.start();
        t2.start();
    }
}
