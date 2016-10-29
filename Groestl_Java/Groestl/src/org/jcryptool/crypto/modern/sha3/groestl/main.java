package org.jcryptool.crypto.modern.sha3.groestl;

import java.nio.charset.Charset;

public class main {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		String str = "0000000000";
		int hashlength = 224;
		GroestlAlgorithm g = new GroestlAlgorithm(hashlength, str.getBytes());        
		byte[] bytes = g.getHash();
		
		final char[] hexArray = "0123456789ABCDEF".toCharArray();
		char[] hexChars = new char[bytes.length * 2];
	    for(int j = 0; j < bytes.length; j++) {
	        int v = bytes[j] & 0xFF;
	        hexChars[j * 2] = hexArray[v >>> 4];
	        hexChars[j * 2 + 1] = hexArray[v & 0x0F];
	    }
	    
	    for(int i = 0; i < hexChars.length; i++)
	    	System.out.print(hexChars[i]);
	}

}
