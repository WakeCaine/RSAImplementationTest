package com.rsa.impl;
import java.math.BigInteger;
import java.util.Random;

public class keysGenerator {
	BigInteger p, q, n, phi, e, d;
	
	public keysGenerator(){
		//1. Prime numbers generation
		p = BigInteger.probablePrime(128, new Random());
		q = BigInteger.probablePrime(128, new Random());
		
		//2. n = p * q
		n = p.multiply(q);
		
		//3. phi = (p - 1)*(q - 1)
		phi = p.subtract(BigInteger.valueOf(1));
		phi = phi.multiply(q.subtract(BigInteger.valueOf(1)));
		
		//4.gcd(e,phi) = 1; 1 < e < phi
		 e = BigInteger.probablePrime(128/2, new Random()); 
        while (phi.gcd(e).compareTo(BigInteger.ONE) > 0 && e.compareTo(phi) < 0 ) { 
            e.add(BigInteger.ONE); 
        } 
        
		//5. e * d = 1 (mod phi)
		d = e.modInverse(phi);
	}
	
	public String getPublicKey(){
		String key = "";
		key += d.toString() + "+" + n.toString();
		return key;
	}
	
	
	//Encrypt your message with a key
	public String cryptString(String plainText, String key){
		String encryptedText = "";
		int checkLength = plainText.length();
		int counter = 0;
		while(checkLength != 0){
			if(checkLength > 3){
				encryptedText += convertToString(xor(plainText.substring(counter, counter+3).getBytes(),key.getBytes()));
				counter+=3;
				checkLength-=3;
			}else if(checkLength == 2){
				encryptedText += convertToString(xor(plainText.substring(counter, counter+2).getBytes(),key.getBytes()));
				counter+=2;
				checkLength-=2;
			}else{
				encryptedText += convertToString(xor(plainText.substring(counter, counter+1).getBytes(),key.getBytes()));
				counter+=1;
				checkLength-=1;
			}
		}
		return encryptedText;
	}
	
	//Decrypt your message with a key
	public String decryptString(String encryptedText, String key){
		String dencryptedText = "";
		int checkLength = encryptedText.length();
		int counter = 0;
		while(checkLength != 0){
			if(checkLength > 3){
				dencryptedText += convertToString(xor(encryptedText.substring(counter, counter+3).getBytes(),key.getBytes()));
				counter+=3;
				checkLength-=3;
			}else if(checkLength == 2){
				dencryptedText += convertToString(xor(encryptedText.substring(counter, counter+2).getBytes(),key.getBytes()));
				counter+=2;
				checkLength-=2;
			}else{
				dencryptedText += convertToString(xor(encryptedText.substring(counter, counter+1).getBytes(),key.getBytes()));
				counter+=1;
				checkLength-=1;
			}
		}
		return dencryptedText;
	}

	//Xor on bytes
	private static byte[] xor(final byte[] input, final byte[] secret) {
	    final byte[] output = new byte[input.length];
	    if (secret.length == 0) {
	        throw new IllegalArgumentException("empty security key");
	    }
	    int spos = 0;
	    for (int pos = 0; pos < input.length; ++pos) {
	        output[pos] = (byte) (input[pos] ^ secret[spos]);
	        ++spos;
	        if (spos >= secret.length) {
	            spos = 0;
	        }
	    }
	    return output;
	}
	
	//Convert byte table to ASCII String
	public String convertToString(byte[] data) {
	    StringBuilder sb = new StringBuilder(data.length);
	    for (int i = 0; i < data.length; ++ i) {
	        if (data[i] < 0) throw new IllegalArgumentException();
	        sb.append((char) data[i]);
	    }
	    return sb.toString();
	}
	
	//Bytes to String
	public static String bytesToString(byte[] encrypted) { 
	        String test = ""; 
	    for (byte b : encrypted) { 
	        test += Byte.toString(b); 
	    } 
	    return test; 
	} 
	     
	//Encrypt key with a public key
	public byte[] encrypt(byte[] message, BigInteger d, BigInteger n) {      
	        return (new BigInteger(message)).modPow(d, n).toByteArray(); 
	   	} 
	       
	// Decrypt key with a private key
	public byte[] decrypt(byte[] message) { 
	        return (new BigInteger(message)).modPow(e, n).toByteArray(); 
	    }  
	
	public String randomKey(){
		String key = new BigInteger(128,new Random()).toString(32);
		if(key.length()>2)
			return key.substring(0, 20);
		else 
			return key;
	}
	
	public String digitString(){
		String key = new BigInteger(2000,new Random()).toString(32);
		if(key.length()>50)
			return key.substring(0, 50);
		else 
			return key;
	}
}
