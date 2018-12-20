package server;

import encryption.*;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.HashMap;
import java.util.Random;
import java.util.Set;
import java.lang.Float;

import java.net.*;

import java.nio.ByteBuffer;
import java.security.spec.X509EncodedKeySpec;
import java.security.PublicKey;
import java.security.KeyFactory;

import java.net.InetAddress;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentLinkedQueue;


public class Server implements Runnable {


	HashMap<Integer, Float> userip2credit;

	private DatagramSocket socket;
	private DatagramSocket socket_sender;
	private byte[] buf = new byte[840];
	HashMap<Integer, PublicKey> publicKeys;
	HashMap<Integer, Integer> phone_and_port;
	private ConcurrentLinkedQueue<DatagramPacket> queue = new ConcurrentLinkedQueue<>();

	//store the packets for each port
	HashMap<Integer, DHPubAndNonce> pubAndNonceOf = new HashMap<>();
	HashMap<Integer, DHPubAndNonceSig> sigOf = new HashMap<>();
	HashMap<Integer,byte[]> sessionKeys = new HashMap<>();
	HashMap<Integer,Message> messages = new HashMap<>();
	HashMap<Integer, ECDH> ephemeralKeysStored = new HashMap<>();

	private TreeSet<Integer> nonces = new TreeSet<>();
	TreeSet<Integer> mNonces = new TreeSet<>();

	HashMap<Integer,TreeSet> DHNonces = new HashMap<>();
	HashMap<Integer,Set> messageNonces = new HashMap<>();


	PrivateKey serverPrivateKey;
	PublicKey serverPublicKey;


	public Server() {

		try {
			FileInputStream file = new FileInputStream("../res/serverPrivateKey.txt");
			byte[] privkey = file.readAllBytes();
			PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(privkey);
			KeyFactory kf = KeyFactory.getInstance("EC");
		    serverPrivateKey = kf.generatePrivate(ks);

			FileInputStream files = new FileInputStream("../res/serverPublicKey.txt");
			byte[] publicKey = files.readAllBytes();
			X509EncodedKeySpec kj = new X509EncodedKeySpec(publicKey);
			KeyFactory kt = KeyFactory.getInstance("EC");
			serverPublicKey = kt.generatePublic(kj);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		userip2credit = new HashMap<Integer, Float>();

		try {
			socket = new DatagramSocket(4445);
			socket_sender = new DatagramSocket(4440);
			publicKeys = new HashMap<Integer, PublicKey>();
			phone_and_port= new HashMap<Integer,Integer>();

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	private Object lock = new Object();
	boolean flag = true;

	public void run_receiver() {

		DatagramPacket packet = new DatagramPacket(buf, buf.length);

		try {
			socket.receive(packet);
		} catch (IOException e) {
			e.printStackTrace();
		}
		queue.add(packet);
		synchronized (lock) {
			flag = false;
			lock.notifyAll();
		}

	}

	public void run_sender() {

		synchronized (lock) {

			while (flag == true) {
				try {
					lock.wait();
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
			}
		}
		flag = true;
		DatagramPacket packet = queue.peek();
		try {

			ByteBuffer bb = ByteBuffer.wrap(packet.getData());
			char op = bb.getChar();
			
			System.out.println();
			System.out.println("Packet received from port - " + packet.getPort() );
			System.out.println("Operation - " + op );
			System.out.println();

			switch (op) {
				case 'B':
					receiveBank(packet);
					break;

				case 'C':
					receiveCert(packet);
					break;

				case 'N':
					int portN =createNewKeys(packet);
					checkIfComplete(portN);
					break;

				case 'R':
					int portR = createNewKeys(packet);
					sendNotify(portR);
					break;

				case 'M':
					declassifyPacket(packet);
					break;

				case 'L':
					int portL = createNewKeys(packet);
					checkIfComplete(portL);
					sendBalance(portL);
					break;

				default:
					break;
			}


		} catch (Exception e) {
			e.printStackTrace();

		}
		queue.remove(packet);
	}


	private void sendBalance(int portL){
		float balance = userip2credit.get(portL);

		byte[] sessionKey = sessionKeys.get(portL);

		try {
			Message message = new Message(4440, portL, 'L', balance);
			MessageAndHash messageAndHash = new MessageAndHash(message);
			CipheredMessage cipheredMessage = new CipheredMessage(messageAndHash, sessionKey, 'L');
			byte[] msg = cipheredMessage.toBytes();


			InetAddress IPAddress = InetAddress.getByName("localhost");

			DatagramPacket sendPacket = new DatagramPacket(msg, msg.length, IPAddress, portL);
			socket_sender.send(sendPacket);
		}catch (Exception e){
			e.printStackTrace();
		}

	}
	private void sendNotify(int port) {

		DHPubAndNonce UserpubAndNonce = pubAndNonceOf.get(port);
		DHPubAndNonceSig Usersig = sigOf.get(port);


		if (UserpubAndNonce != null && Usersig != null) {

			PublicKey UserPub = publicKeys.get(port);
			ECDH ephemeralKeys = ephemeralKeysStored.get(port);

			try {
				//check if the user has complete the DH process and if so return the sig of their DHpub and nonce
				// signed with the server PrivKey
				boolean completeDH = Usersig.verify(UserpubAndNonce, UserPub);

				if (completeDH) {

					//calculate shared secret with the users DH pub and server long term pub
					PublicKey userDHPub = UserpubAndNonce.getKey();
					byte[] shared_secret = ECUtil.genSharedSecret(ephemeralKeys.getPrivateKey(), userDHPub, ephemeralKeys.getPublicKey());

					sessionKeys.put(port, shared_secret);

					System.out.println("Shared secret with user " + ECUtil.bytesToHex(shared_secret));
					System.out.println();

					Message message = messages.get(port);
					MessageAndHash messageAndHash = new MessageAndHash(message);
					CipheredMessage cipheredMessage = new CipheredMessage(messageAndHash, shared_secret, 'M');
					byte[] msg = cipheredMessage.toBytes();


					InetAddress IPAddress = InetAddress.getByName("localhost");

					DatagramPacket sendPacket = new DatagramPacket(msg, msg.length, IPAddress, port);
					socket_sender.send(sendPacket);

				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	private void declassifyPacket(DatagramPacket packet) {

		int port = packet.getPort() + 1000;
		byte[] sessionKey = sessionKeys.get(port);

		CipheredMessage ciphMessage = new CipheredMessage(packet.getData());
		MessageAndHash mh = null;
		try {
			mh = ciphMessage.decipher(sessionKey);
		} catch (Exception e) {
			e.printStackTrace();
		}

		try {
			if(mh.isValid()){
				Message m = mh.getMessage();
				int destination = m.getDestination();

				float value = m.getValue();
				float originCredit = userip2credit.get(port);
				originCredit -= value;
				userip2credit.put(port,originCredit);

				int destinationPort = phone_and_port.get(destination);

				float destCredit = userip2credit.get(destinationPort);
				userip2credit.put(destinationPort,destCredit+value);
				messages.put(destinationPort,m);

				ECDH ephemeralKeys = new ECDH();
				ephemeralKeysStored.put(destinationPort,ephemeralKeys);

				DHPubAndNonce dhPubAndNonce = new DHPubAndNonce(ephemeralKeys.getPublicKey(),new Random().nextInt(),'N');
				DHPubAndNonceSig dhPubAndNonceSig = new DHPubAndNonceSig(dhPubAndNonce,serverPrivateKey,'N');
				sendDH(dhPubAndNonce,dhPubAndNonceSig,destinationPort);

			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		ByteBuffer bb = ByteBuffer.wrap(packet.getData());
		char operation = bb.getChar();
		int sm   = bb.getInt();

	}




	private int createNewKeys(DatagramPacket packet) {

		int port = packet.getPort() + 1000;


		ByteBuffer bb = ByteBuffer.wrap(packet.getData());
		char operation = bb.getChar();
		int sm   = bb.getInt();

		if( sm == 1 ){
			try {
				DHPubAndNonce dhPubandNonce = new DHPubAndNonce(packet.getData());

				TreeSet<Integer> nonces = DHNonces.get(port);
				if(nonces!=null) {

					if (nonces.contains(dhPubandNonce.getNonce())) {
						return -1;
					} else {
						nonces.add(dhPubandNonce.getNonce());
						DHNonces.put(port, nonces);
					}
				}
				else {
					pubAndNonceOf.put(port, dhPubandNonce);
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		if( sm == 2 ){
			try {
				sigOf.put(port, new DHPubAndNonceSig( packet.getData() ) );
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		return port;

	}


	public void checkIfComplete( int port ){

		DHPubAndNonce UserpubAndNonce = pubAndNonceOf.get(port);
		DHPubAndNonceSig Usersig      = sigOf.get(port);


		if( UserpubAndNonce!=null && Usersig != null ){

			PublicKey UserPub = publicKeys.get(port);
			ECDH ephemeralKeys = new ECDH();


			try{
				//check if the user has complete the DH process and if so return the sig of their DHpub and nonce
				// signed with the server PrivKey
				boolean completeDH = Usersig.verify(UserpubAndNonce, UserPub);

				if(completeDH){

					//calculate shared secret with the users DH pub and server long term pub
					PublicKey userDHPub = UserpubAndNonce.getKey();
					byte[] shared_secret = ECUtil.genSharedSecret(ephemeralKeys.getPrivateKey(), userDHPub,ephemeralKeys.getPublicKey());

					sessionKeys.put(port,shared_secret);

					System.out.println("Shared secret with user " + ECUtil.bytesToHex(shared_secret) );
					System.out.println();

					//create the signature
					DHPubAndNonce pub = new DHPubAndNonce(ephemeralKeys.getPublicKey(),new Random().nextInt(),'R');
					DHPubAndNonceSig publicSig = null;
					try {
						publicSig = new DHPubAndNonceSig(pub,serverPrivateKey,'R');
					} catch (Exception e) {
						e.printStackTrace();
					}


					sendDH(pub,publicSig,port);
				}
			}
			catch(Exception e){
				e.printStackTrace(System.out);
			}
		}
	}

	private void sendDH(DHPubAndNonce userDHPub, DHPubAndNonceSig serverSig,int port) {
		InetAddress ip = null;

		try {
			ip = InetAddress.getByName("localhost");
		} catch (UnknownHostException e) {
			e.printStackTrace();
		}

		byte[] firstpacket = userDHPub.toBytes();
		byte[] secondpacket = serverSig.toBytes();
		DatagramPacket packet = new DatagramPacket(firstpacket,firstpacket.length,ip,port);
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
		DatagramPacket packet2 = new DatagramPacket(secondpacket,secondpacket.length,ip,port);
		try {
			socket_sender.send(packet2);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}


	private void receiveCert(DatagramPacket packet) {
		int portNr = packet.getPort();
		portNr -=1000;

		ByteBuffer bb = ByteBuffer.wrap(packet.getData());

		char op = bb.getChar();

		int phoneNr = bb.getInt();
		phone_and_port.put(phoneNr,portNr);
		userip2credit.put(portNr,(float)500);

		byte[] pubKey = new byte[80];
		bb.get(pubKey);

		try {
			X509EncodedKeySpec ks = new X509EncodedKeySpec(pubKey);
			KeyFactory kf = KeyFactory.getInstance("EC");
			PublicKey publicKey = kf.generatePublic(ks);
			publicKeys.put(portNr, publicKey);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private void receiveBank(DatagramPacket packet) {
		int portNr = packet.getPort();
		portNr -=2000;

		ByteBuffer bb = ByteBuffer.wrap(packet.getData());

		char op = bb.getChar();
		System.out.println(op);

		int phoneNr = bb.getInt();
		System.out.println(phoneNr);

		Float val = bb.getFloat();
		System.out.println(val);

		if (userip2credit.containsKey(portNr)) {
			Float credito = userip2credit.get(portNr);
			credito = Float.sum(credito, val);
			userip2credit.put(portNr, credito);
			System.out.println("port:"+ portNr + "cred:" + credito);

		} else {
			userip2credit.put(portNr, val);
			System.out.println("port:"+ portNr + "cred:" + val);
		}

	}

	@Override
	public void run() {
		while (true) {
			if (Thread.currentThread().getName().equals("thread1")) {
				run_receiver();
			} else {
				run_sender();
			}
		}
	}

}

