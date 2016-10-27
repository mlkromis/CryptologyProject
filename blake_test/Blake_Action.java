package blake;

import java.util.Arrays;

public class Blake_Action {
	public static void main(String[] args) {
		short[] hash;
		short[] data= new short[144];
		int hashbitlen = 384;
		int databitlen = 8;
		Arrays.fill(data, (short)0);
		Blake_Algorithm blake = new Blake_Algorithm(hashbitlen, data, databitlen);
		hash = blake.getHash();
		final StringBuilder builder = new StringBuilder();
	    for(short b : hash) {
	        builder.append(String.format("%02x", b));
	    }
	    System.out.println(builder.toString());
		
	}
}
