package blake;

import java.util.Arrays;

public class Blake_Action {
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		short[] hash;
		short[] data= new short[144];
		int hashbitlen = 256;
		int databitlen = 8;
		Arrays.fill(data, (short)0);
		System.out.println("Hello World!");
		Blake_Algorithm blake = new Blake_Algorithm(hashbitlen, data, databitlen);
		hash = blake.getHash();
		System.out.println(Arrays.toString(data));
		System.out.println(Arrays.toString(hash));
		
	}
}
