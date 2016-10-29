package blake;

import java.util.Arrays;

public class Blake_Action {
	public static void main(String[] args) {
		byte[] hash;
		byte[] data= new byte[144];
		int hashbitlen = 256;
		String salt = "af23456789ab3465af23456789ab3465";
		Arrays.fill(data, (byte)0);
		Blake_Algorithm blake = new Blake_Algorithm(hashbitlen, data, salt);
		hash = blake.getHash();
		final StringBuilder builder = new StringBuilder();
	    for(byte b : hash) {
	        builder.append(String.format("%02x", b));
	    }
	    System.out.println(builder.toString());
		
	}
}
