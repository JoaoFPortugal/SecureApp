package server;

import java.net.InetAddress;
import java.util.HashMap;
import java.security.PublicKey;


public class AccountManager{



	HashMap<Integer,Float> balanceOf;
	//HashMap<Integer,InetAddress> inetAddOf; 
	//HashMap<Integer,PublicKey> pubKeyOf;


	public AccountManager(){

		this.balanceOf = new HashMap<Integer,Float>();
		//this.inetAddOf = new HashMap<Integer,InetAddress>();
		//this.pubKeyOf  = new HashMap<Integer,PublicKey>();
	}




	public void newUser(int phonenumber) throws Exception{

		if(!balanceOf.containsKey(phonenumber)){
			balanceOf.put(phonenumber, (float)(0));
		}
		else{
			throw new Exception( "Phone number " + phonenumber + "already has an account");
		}

	}




	public Boolean isValid( int phonenumber ){

		return phonenumber>0 && String.valueOf(phonenumber).length()==9;

	}



	public boolean hasAccount(int phonenumber){

		if( isValid(phonenumber) ){
			return balanceOf.containsKey(phonenumber);
		}
		else{
			return false;
		}
	}


	public Float getBalance( Integer phonenumber ) throws Exception{

		if( hasAccount(phonenumber) ){

			return balanceOf.get(phonenumber);
		}

		else{

			throw new Exception("Invalid user id");
		}

	}


	public void setBalance( Integer phonenumber, Float amount ) throws Exception{


		if( hasAccount(phonenumber) ){

			if(amount >= 0){

				balanceOf.put(phonenumber, amount);

			}
			else{
				throw new Exception("Invalid amount");
			}

		}
		else{

			throw new Exception("Invalid user id");
		}

	}






	public void transfer( Integer src, Integer dest, Float amount ) throws Exception{


		if( hasAccount(src) && hasAccount(dest) ){

			if( getBalance(src) >= amount ){

				setBalance( dest, getBalance(dest) + amount );

			}
			else{
				throw new Exception("Insuffient funds");
			}
		}


		else{
			throw new Exception("Invalid dest or src phone numbers");
		}

	}




	public void print(){

		Float user_balance;

		for(Integer phonenumber: balanceOf.keySet()){

			try{ 
				user_balance= getBalance(phonenumber);
			}
			catch(Exception e){
				user_balance = (float)(-1) ;
			}


			System.out.printf("user %d , Balance %f\n", phonenumber, user_balance);

		}


	}

}