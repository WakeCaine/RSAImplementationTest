package com.main;

import java.util.Scanner;
import java.io.DataInputStream;
import java.io.IOException;
import java.math.BigInteger;

import com.rsa.impl.keysGenerator;

public class RSATest {
	
	@SuppressWarnings("deprecation")
	public static void main(String[] args) throws IOException {
		Scanner s = new Scanner(System.in);
		BigInteger d, n;
		DataInputStream in=new DataInputStream(System.in);  
		int check = 0;
		int input = 0;
		String publicKey="";
		String keyK="";
		byte[] keyE=null;
		byte[] encryptedW = null;
		keysGenerator rsa = null;
		String teststring1="";
		
		do{
			System.out.println("Wybierz jedn¹ z opcji:");
			System.out.println("1- Generowanie klucza publicznego:");
			System.out.println("2- Tworzenie wiadomoœci przy pomocy wygenerowanego klucza:");
			System.out.println("3- Odszyfrowanie wiadomoœci:");
			input = Integer.parseInt(s.nextLine());
			switch(input)
			{
				case 1:
				{
					rsa = new keysGenerator(); 
					publicKey = rsa.getPublicKey();
					System.out.println("Klucz publiczny d+n: " +publicKey);
					s.nextLine();
					break;
				}
				case 2:
				{
					int choose=1;
				    System.out.println("Enter the plain text or generate plain text?(1 or 2)");
				    choose=Integer.parseInt(s.nextLine());
				    switch(choose){
					    case 1:
					    {
					    	teststring1 = in.readLine();
					    	break;
					    }
					    case 2:
					    {
					    	teststring1=rsa.digitString();
					    	break;
					    }
				    }
				    System.out.println("Wiadomosc: " +teststring1);
				    System.out.println("Klucz publiczny d+n: " +publicKey);
				    //Generate key to encrypt
				    String key = rsa.randomKey();
				    teststring1 = rsa.cryptString(teststring1, key); //wiadomoœæ zaszyfrowana xor z kluczem
				    System.out.println("Key to Encrypt: \"" + key + "\""); 
				    System.out.println("Encrypted Message: \"" + teststring1 + "\""); 
				    
				    keyK=key;
				    //System.out.println("String in Bytes: " + rsa.bytesToString(key.getBytes())); 
				    System.out.println("Wprowadz d?");
				    d=new BigInteger(in.readLine());
				    System.out.println("Wprowadz n?");
				    n=new BigInteger(in.readLine());
				    //Encrypt key
				    //System.out.println(key.getBytes());
				    encryptedW = rsa.encrypt(key.getBytes(), d, n);
				    System.out.println("Encrypted key in Bytes: " + rsa.bytesToString(encryptedW));
				    s.nextLine();
					break;
				}
					
				case 3:
				{
					byte[] decrypted = rsa.decrypt(encryptedW); 
			        //System.out.println(decrypted);
			        System.out.println("Decrypted key in Bytes: " +  rsa.bytesToString(decrypted)); 
			        keyK=rsa.convertToString(decrypted);
			        System.out.println("Decrypted key in String: \"" + rsa.decryptString(teststring1, rsa.convertToString(decrypted))+"\"");
			        
			        s.nextLine();
					break;
				}
				default:
					break;
			}
		}while(check == 0);
		
		rsa = new keysGenerator(); 
        
        String teststring ;
        System.out.println("Enter the plain text:");
        teststring=rsa.digitString();
        System.out.println(teststring);
        System.out.println(rsa.getPublicKey());
        //Generate key to encrypt
        String key = rsa.randomKey();
        teststring = rsa.cryptString(teststring, key); //wiadomoœæ zaszyfrowana xor z kluczem

        System.out.println("Encrypted Message: \"" + teststring + "\""); 
        System.out.println("Encrypting Key: \"" + key + "\""); 
        //System.out.println("String in Bytes: " + rsa.bytesToString(key.getBytes())); 
        System.out.println("d?");
        d=new BigInteger(in.readLine());
        System.out.println("n?");
        n=new BigInteger(in.readLine());
        //Encrypt key
        //System.out.println(key.getBytes());
        byte[] encrypted = rsa.encrypt(key.getBytes(), d, n);   
        System.out.println("Encrypted key in Bytes: " + rsa.bytesToString(encrypted));
        
        
        // decrypt 
        
        byte[] decrypted = rsa.decrypt(encrypted); 
        //System.out.println(decrypted);
        System.out.println("Decrypted key in Bytes: " +  rsa.convertToString(decrypted)); 
        key=rsa.convertToString(decrypted);
        System.out.println("Decrypted key in String: \"" + rsa.decryptString(teststring, rsa.convertToString(decrypted))+"\"");
        
        //System.out.println(rsa.cryptString("jdsbfdsbfsdbfasdvdsgvgvdsjdshjdshjvbfd", "sdf"));
        //System.out.println(rsa.decryptString(rsa.cryptString("jdsbfdsbfsdbfasdvdsgvgvdsjdshjdshjvbfd", "sdf"), "sdf"));
        //System.out.println(rsa.randomKey());
	}
}
