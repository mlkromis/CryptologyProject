import java.util.Arrays;


public class Test{
	 private static int U8TO32_BE(byte[] p){
		    int q = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
		    System.out.println(Integer.toHexString(p[0]));
		    System.out.println(Integer.toHexString(p[1]));
		    System.out.println(Integer.toHexString(p[1] << 16));
		       return q; }	    
	 private static long U8TO64_BE(byte[] p){
		    	byte [] pp=	Arrays.copyOfRange(p, 4, p.length);
		    	long q=(((long)U8TO32_BE(p))<<32 | (long)U8TO32_BE(pp));
		        return q;
		    }
	 private static byte[] U32TO8_BE(int v){
	    	byte [] p=new byte[4];
	    	p[0]=(byte)((v)>>24);
	        p[1]=(byte)((v)>>16);
	        p[2]=(byte)((v)>>8);
	        p[3]=(byte)((v));
	    	return p;
	    }
	 
	private static byte[] U64TO8_BE(long v){ 
 	byte [] p1=U32TO8_BE((int)((v) >> 32));	
 	byte [] p2=U32TO8_BE((int)((v)));
 	byte [] p3=new byte[8];
 	for(int i=0; i<4; i++) {
 		Arrays.fill(p3, i, i, p1[i]);
 		Arrays.fill(p3, i+4, i+4, p2[i]);
 	}
 	return p3;    
 }
	public static void main(String[] args){
		byte [] p={(byte) 0x7f, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff};
		System.out.println(Integer.toHexString((int)(byte)0x00ff));
		int v=U8TO32_BE(p);
		System.out.println(Integer.toHexString(v));
		long v1=U8TO64_BE(p);
		System.out.println(v1);
		p=U32TO8_BE(v);
		byte [] p1=new byte[8];
		p1=U64TO8_BE(v1);
		System.out.println(p[0]);
		System.out.println(p1[0]);
	}
}