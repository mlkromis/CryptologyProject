package blake;

import java.nio.ShortBuffer;
import java.util.Arrays;

public class Blake_Algorithm {
	private int SUCCESS=0;
    private int FAIL=1;
    private int BAD_HASHBITLEN=2;
    
    private Blake_HashState state;
    private short hashval[];
    private int status;
    
    public static final short padding[] =
        {
          (short)0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
      };
    
    /*
    constants for BLAKE-32 and BLAKE-28
  */
  public static final long c32[] = {
      0x243F6A88, 0x85A308D3,
      0x13198A2E, 0x03707344,
      0xA4093822, 0x299F31D0,
      0x082EFA98, 0xEC4E6C89,
      0x452821E6, 0x38D01377,
      0xBE5466CF, 0x34E90C6C,
      0xC0AC29B7, 0xC97C50DD,
      0x3F84D5B5, 0xB5470917 
  };

  /*
    constants for BLAKE-64 and BLAKE-48
  */
  public static final long c64[] = {
          0x243F6A8885A308D3L,0x13198A2E03707344L,
          0xA4093822299F31D0L,0x082EFA98EC4E6C89L,
          0x452821E638D01377L,0xBE5466CF34E90C6CL,
          0xC0AC29B7C97C50DDL,0x3F84D5B5B5470917L,
          0x9216D5D98979FB1BL,0xD1310BA698DFB5ACL,
          0x2FFD72DBD01ADFB7L,0xB8E1AFED6A267E96L,
          0xBA7C9045F12C7F99L,0x24A19947B3916CF7L,
          0x0801F2E2858EFC16L,0x636920D871574E69L
        };
  /*public static final BigInteger c64[] = {
    new BigInteger("0x243F6A8885A308D3"),new BigInteger("0x13198A2E03707344"),
    new BigInteger("0xA4093822299F31D0"),new BigInteger("0x082EFA98EC4E6C89"),
    new BigInteger("0x452821E638D01377"),new BigInteger("0xBE5466CF34E90C6C"),
    new BigInteger("0xC0AC29B7C97C50DD"),new BigInteger("0x3F84D5B5B5470917"),
    new BigInteger("0x9216D5D98979FB1B"),new BigInteger("0xD1310BA698DFB5AC"),
    new BigInteger("0x2FFD72DBD01ADFB7"),new BigInteger("0xB8E1AFED6A267E96"),
    new BigInteger("0xBA7C9045F12C7F99"),new BigInteger("0x24A19947B3916CF7"),
    new BigInteger("0x0801F2E2858EFC16"),new BigInteger("0x636920D871574E69")
  };*/
    
    public static final int IV256[]={
         0x6A09E667, 0xBB67AE85,
         0x3C6EF372, 0xA54FF53A,
         0x510E527F, 0x9B05688C,
         0x1F83D9AB, 0x5BE0CD19
       };
    public static final int IV224[]={
         0xC1059ED8, 0x367CD507,
         0x3070DD17, 0xF70E5939,
         0xFFC00B31, 0x68581511,
         0x64F98FA7, 0xBEFA4FA4
       };
    public static final long IV384[]={
            0xCBBB9D5DC1059ED8L, 0x629A292A367CD507L,
            0x9159015A3070DD17L, 0x152FECD8F70E5939L,
            0x67332667FFC00B31L, 0x8EB44A8768581511L,
            0xDB0C2E0D64F98FA7L, 0x47B5481DBEFA4FA4L
        };
    public static final long IV512[]={
            0x6A09E667F3BCC908L, 0xBB67AE8584CAA73BL,
            0x3C6EF372FE94F82BL, 0xA54FF53A5F1D36F1L,
            0x510E527FADE682D1L, 0x9B05688C2B3E6C1FL,
            0x1F83D9ABFB41BD6BL, 0x5BE0CD19137E2179L
          };
   /* public static final BigInteger IV384[]={
         new BigInteger("0xCBBB9D5DC1059ED8"), new BigInteger("0x629A292A367CD507"),
         new BigInteger("0x9159015A3070DD17"), new BigInteger("0x152FECD8F70E5939"),
         new BigInteger("0x67332667FFC00B31"), new BigInteger("0x8EB44A8768581511"),
         new BigInteger("0xDB0C2E0D64F98FA7"), new BigInteger("0x47B5481DBEFA4FA4")
       };*/
   /* public static final BigInteger IV512[]={
         new BigInteger("0x6A09E667F3BCC908"), new BigInteger("0xBB67AE8584CAA73B"),
         new BigInteger("0x3C6EF372FE94F82B"), new BigInteger("0xA54FF53A5F1D36F1"),
         new BigInteger("0x510E527FADE682D1"), new BigInteger("0x9B05688C2B3E6C1F"),
         new BigInteger("0x1F83D9ABFB41BD6B"), new BigInteger("0x5BE0CD19137E2179")
       };
    */
    private static short sigma[][] = {
            {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
            { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 } ,
            { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 } ,
            {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 } ,
            {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 } ,
            {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 } ,
            { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 } ,
            { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 } ,
            {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 } ,
            { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 }, 
            {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
            { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 } ,
            { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 } ,
            {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 } ,
            {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 } ,
            {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 } ,
            { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 } ,
            { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 } ,
            {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 } ,
            { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 }  
          };

    
    Blake_Algorithm(int hashbitlen, short[] data, int databitlen){
        this.status = FAIL;
        this.hashval = new short[hashbitlen/8];
        this.state = new Blake_HashState();

        status = Hash(hashbitlen,data,databitlen);
        System.out.println(status);
    }

    Blake_Algorithm(int hashbitlen, short[] data, int databitlen, String salt){
        this.status = FAIL;
        this.hashval = new short[hashbitlen/8];
        this.state = new Blake_HashState();

        //AddSalt(hexStrToshortField(salt));

        status = Hash(hashbitlen,data,databitlen);
    }
    
    public int getStatus(){
        return this.status;
    }

    public short[] getHash(){
        return this.hashval;
    }
    
    private long ROT32(long x, long n){
        return (((x<<(32-n))|(x>>n))& 0xffffffffL);
    }
    
    private long ADD32(long x, long y){
        return ((x + y) & 0xffffffffL);
    }
    
    private long XOR32(long x, long y){
        return ((x ^ y) & 0xffffffffL);
    }
    
    private long[] G32(long v[], long m[], short round,
                    int a, int b, int c, int d, int i){ 
        v[a] = ADD32(v[a],v[b])+XOR32(m[sigma[round][2*i]], c32[sigma[round][2*i+1]]);
        v[d] = ROT32(XOR32(v[d],v[a]),16);
        v[c] = ADD32(v[c],v[d]);
        v[b] = ROT32(XOR32(v[b],v[c]),12);
        v[a] = ADD32(v[a],v[b])+XOR32(m[sigma[round][2*i+1]], c32[sigma[round][2*i]]);
        v[d] = ROT32(XOR32(v[d],v[a]), 8);
        v[c] = ADD32(v[c],v[d]);
        v[b] = ROT32(XOR32(v[b],v[c]), 7);
        
        return v;
      }
    
    private int compress32(short[] datablock){
 
        long v[] = new long[16];
        long m[] = new long[16];
        short check[] = new short[4];
        short round;

    //  #define ROT32(x,n) (((x)<<(32-n))|( (x)>>(n)))
    //  #define ADD32(x,y)   ((u32)((x) + (y)))
    //  #define XOR32(x,y)    ((u32)((x) ^ (y)))

        /* get message */
        check = Arrays.copyOfRange(datablock,0,3);
        System.out.println(Arrays.toString(check));
        m[0] = U8TO32_BE(Arrays.copyOfRange(datablock,0,4));
        m[1] = U8TO32_BE(Arrays.copyOfRange(datablock,4,8));
        m[2] = U8TO32_BE(Arrays.copyOfRange(datablock,8,12));
        m[3] = U8TO32_BE(Arrays.copyOfRange(datablock,12,16));
        m[4] = U8TO32_BE(Arrays.copyOfRange(datablock,16,20));
        m[5] = U8TO32_BE(Arrays.copyOfRange(datablock,20,24));
        m[6] = U8TO32_BE(Arrays.copyOfRange(datablock,24,28));
        m[7] = U8TO32_BE(Arrays.copyOfRange(datablock,28,32));
        m[8] = U8TO32_BE(Arrays.copyOfRange(datablock,32,36));
        m[9] = U8TO32_BE(Arrays.copyOfRange(datablock,36,40));
        m[10] = U8TO32_BE(Arrays.copyOfRange(datablock,40,44));
        m[11] = U8TO32_BE(Arrays.copyOfRange(datablock,44,48));
        m[12] = U8TO32_BE(Arrays.copyOfRange(datablock,48,52));
        m[13] = U8TO32_BE(Arrays.copyOfRange(datablock,52,56));
        m[14] = U8TO32_BE(Arrays.copyOfRange(datablock,56,60));
        m[15] = U8TO32_BE(Arrays.copyOfRange(datablock,60,64));

        /* initialization */
        v[ 0] = state.h32[0] & 0xffffffffL;
        v[ 1] = state.h32[1] & 0xffffffffL;
        v[ 2] = state.h32[2] & 0xffffffffL;
        v[ 3] = state.h32[3] & 0xffffffffL;
        v[ 4] = state.h32[4] & 0xffffffffL;
        v[ 5] = state.h32[5] & 0xffffffffL;
        v[ 6] = state.h32[6] & 0xffffffffL;
        v[ 7] = state.h32[7] & 0xffffffffL;
        v[ 8] = (state.salt32[0] ^ c32[0]) & 0xffffffffL;
        v[ 9] = (state.salt32[1] ^ c32[1]) & 0xffffffffL;
        v[10] = (state.salt32[2] ^ c32[2]) & 0xffffffffL;
        v[11] = (state.salt32[3] ^ c32[3]) & 0xffffffffL;
        if (state.nullt != 0) { /* special case t=0 for the last block */
          v[12] =  c32[4] & 0xffffffffL;
          v[13] =  c32[5] & 0xffffffffL;
          v[14] =  c32[6] & 0xffffffffL;
          v[15] =  c32[7] & 0xffffffffL;
        }
        else {
          v[12] = (state.t32[0] ^ c32[4]) & 0xffffffffL;
          v[13] = (state.t32[0] ^ c32[5]) & 0xffffffffL;
          v[14] = (state.t32[1] ^ c32[6]) & 0xffffffffL;
          v[15] = (state.t32[1] ^ c32[7]) & 0xffffffffL;
        }

        /*  do 14 rounds */
        for(round=0; round<14; ++round) {

          /* column step */
          v = G32(v, m, round, 0, 4, 8,12, 0);
          v = G32(v, m, round, 1, 5, 9,13, 1);
          v = G32(v, m, round, 2, 6,10,14, 2);
          v = G32(v, m, round, 3, 7,11,15, 3);    

          /* diagonal step */
          v = G32(v, m, round, 0, 5,10,15, 4);
          v = G32(v, m, round, 1, 6,11,12, 5);
          v = G32(v, m, round, 2, 7, 8,13, 6);
          v = G32(v, m, round, 3, 4, 9,14, 7);

        }

        /* finalization */
        state.h32[0] ^= v[ 0]^v[ 8]^state.salt32[0];
        state.h32[1] ^= v[ 1]^v[ 9]^state.salt32[1];
        state.h32[2] ^= v[ 2]^v[10]^state.salt32[2];
        state.h32[3] ^= v[ 3]^v[11]^state.salt32[3];
        state.h32[4] ^= v[ 4]^v[12]^state.salt32[0];
        state.h32[5] ^= v[ 5]^v[13]^state.salt32[1];
        state.h32[6] ^= v[ 6]^v[14]^state.salt32[2];
        state.h32[7] ^= v[ 7]^v[15]^state.salt32[3];

        return SUCCESS;
    }
    
    private long ROT64(long x, int n){
        long y;
        y = x << (64-n);
        return y | (x >> n);
    }
    
    private long ADD64(long x, long y){
        return (x + y);
    }
    
    private long XOR64(long x, long y){
        return (x ^ y);
    }
    
    private long[] G64(long v[], long m[], short round,
            int a, int b, int c, int d, int i){ 
      v[a] = ADD64(v[a],v[b])+XOR64(m[sigma[round][2*i]], c64[sigma[round][2*i+1]]);
      v[d] = ROT64(XOR64(v[d],v[a]),32);
      v[c] = ADD64(v[c],v[d]);
      v[b] = ROT64(XOR64(v[b],v[c]),25);
      v[a] = ADD64(v[a],v[b])+XOR64(m[sigma[round][2*i+1]], c64[sigma[round][2*i]]);
      v[d] = ROT64(XOR64(v[d],v[a]),16);
      v[c] = ADD64(v[c],v[d]);
      v[b] = ROT64(XOR64(v[b],v[c]),11);
      
      return v;
    }
    
    private long compress64(short[] data ) {

        long v[] = {0};
        long m[] = {0};
        short round;

        /* get message */
        m[0] = U8TO64_BE(Arrays.copyOfRange(data,0,3));
        m[1] = U8TO64_BE(Arrays.copyOfRange(data,4,7));
        m[2] = U8TO64_BE(Arrays.copyOfRange(data,8,11));
        m[3] = U8TO64_BE(Arrays.copyOfRange(data,12,15));
        m[4] = U8TO64_BE(Arrays.copyOfRange(data,16,19));
        m[5] = U8TO64_BE(Arrays.copyOfRange(data,20,23));
        m[6] = U8TO64_BE(Arrays.copyOfRange(data,24,27));
        m[7] = U8TO64_BE(Arrays.copyOfRange(data,28,31));
        m[8] = U8TO64_BE(Arrays.copyOfRange(data,32,35));
        m[9] = U8TO64_BE(Arrays.copyOfRange(data,36,39));
        m[10] = U8TO64_BE(Arrays.copyOfRange(data,40,43));
        m[11] = U8TO64_BE(Arrays.copyOfRange(data,44,47));
        m[12] = U8TO64_BE(Arrays.copyOfRange(data,48,51));
        m[13] = U8TO64_BE(Arrays.copyOfRange(data,52,55));
        m[14] = U8TO64_BE(Arrays.copyOfRange(data,56,59));
        m[15] = U8TO64_BE(Arrays.copyOfRange(data,60,63));

        /* initialization */
        v[0] = state.h64[0];
        v[1] = state.h64[1];
        v[2] = state.h64[2];
        v[3] = state.h64[3];
        v[4] = state.h64[4];
        v[5] = state.h64[5];
        v[6] = state.h64[6];
        v[7] = state.h64[7];
        v[ 8] = state.salt64[0] ^ c64[0];
        v[ 9] = state.salt64[1] ^ c64[1];
        v[10] = state.salt64[2] ^ c64[2];
        v[11] = state.salt64[3] ^ c64[3];
        /*v[8] = c64[0].xor(state.salt64[0]);
        v[9] = c64[1].xor(state.salt64[1]);
        v[10] = c64[2].xor(state.salt64[2]);
        v[11] = c64[3].xor(state.salt64[3]);*/
        if (state.nullt != 0) { 
          v[12] =  c64[4];
          v[13] =  c64[5];
          v[14] =  c64[6];
          v[15] =  c64[7];
        }
        else {
          v[12] = state.t64[0] ^ c64[4];
          v[13] = state.t64[0] ^ c64[5];
          v[14] = state.t64[1] ^ c64[6];
          v[15] = state.t64[1] ^ c64[7];
          /*v[12] = c64[4].xor(state.salt64[0]);
          v[13] = c64[5].xor(state.salt64[0]);
          v[14] = c64[6].xor(state.salt64[1]);
          v[15] = c64[7].xor(state.salt64[1]);*/
        }  

        /*  do 16 rounds */
        for(round=0; round<16; ++round) {

          /* column step */
          v = G64(v, m, round, 0, 4, 8,12, 0);
          v = G64(v, m, round, 1, 5, 9,13, 1);
          v = G64(v, m, round, 2, 6,10,14, 2);
          v = G64(v, m, round, 3, 7,11,15, 3);    
          /* diagonal step */
          v = G64(v, m, round, 0, 5,10,15, 4);
          v = G64(v, m, round, 1, 6,11,12, 5);
          v = G64(v, m, round, 2, 7, 8,13, 6);
          v = G64(v, m, round, 3, 4, 9,14, 7);
        }


        /* finalization */
        state.h64[0] ^= v[ 0]^v[ 8]^state.salt64[0];
        state.h64[1] ^= v[ 1]^v[ 9]^state.salt64[1];
        state.h64[2] ^= v[ 2]^v[10]^state.salt64[2];
        state.h64[3] ^= v[ 3]^v[11]^state.salt64[3];
        state.h64[4] ^= v[ 4]^v[12]^state.salt64[0];
        state.h64[5] ^= v[ 5]^v[13]^state.salt64[1];
        state.h64[6] ^= v[ 6]^v[14]^state.salt64[2];
        state.h64[7] ^= v[ 7]^v[15]^state.salt64[3];
       /* state.h64[0] = state.h64[0].xor(v[ 0].xor(v[ 8].xor(state.salt64[0])));
        state.h64[1] = state.h64[1].xor(v[ 1].xor(v[ 9].xor(state.salt64[1])));
        state.h64[2] = state.h64[2].xor(v[ 2].xor(v[10].xor(state.salt64[2])));
        state.h64[3] = state.h64[3].xor(v[ 3].xor(v[11].xor(state.salt64[3])));
        state.h64[4] = state.h64[4].xor(v[ 4].xor(v[12].xor(state.salt64[0])));
        state.h64[5] = state.h64[5].xor(v[ 5].xor(v[13].xor(state.salt64[1])));
        state.h64[6] = state.h64[6].xor(v[ 6].xor(v[14].xor(state.salt64[2])));
        state.h64[7] = state.h64[7].xor(v[ 7].xor(v[15].xor(state.salt64[3])));*/

        return SUCCESS;
      }
    
    private int Init(int hashbitlen){
        int i;
        
        if ( (hashbitlen == 224) || (hashbitlen == 256) )  {
            
            if (hashbitlen == 224) 
                System.arraycopy(IV224, 0, state.h32, 0, IV224.length);      
              else 
            	System.out.println("IV256[1]");
            	System.out.println(Integer.toHexString(IV256[1]));
                System.arraycopy(IV256, 0, state.h32, 0, IV256.length);
                System.out.println("state.h32[1]");
                System.out.println(Integer.toHexString(state.h32[1]));

              state.t32[0] = 0;
              state.t32[1] = 0;

              for(i=0; i<64; ++i)
                state.data32[i] = 0;

              state.salt32[0] = 0;
              state.salt32[1] = 0;
              state.salt32[2] = 0;
              state.salt32[3] = 0;
               
            }
            else if ( (hashbitlen == 384) || (hashbitlen == 512) ){
              /* 384- and 512-bit versions (64-bit words) */

              if (hashbitlen == 384) 
                System.arraycopy(IV384, 0, state.h64, 0, IV384.length);      
              else 
                System.arraycopy(IV512, 0, state.h64, 0, IV512.length );

              state.t64[0] = 0;
              state.t64[1] = 0;

              for(i=0; i<64; ++i)
                state.data64[i] = 0;
              
              state.salt64[0] = 0;
              state.salt64[1] = 0;
              state.salt64[2] = 0;
              state.salt64[3] = 0;    

              
            }
            else
              return BAD_HASHBITLEN;

            state.hashbitlen = (short)hashbitlen;
            state.datalen = 0;
            state.init = 1;
            state.nullt = 0;

            return SUCCESS;
    }
    
    private int AddSalt(short[] salt ) {


        /* if hashbitlen=224 or 256, then the salt should be 128-bit (16 shorts) */
        /* if hashbitlen=384 or 512, then the salt should be 256-bit (32 shorts) */

        /* fail if Init() was not called before */
        if (state.init != 1) 
          return FAIL;

        if ( state.hashbitlen < 384 ) {
          state.salt32[0] = U8TO32_BE(Arrays.copyOfRange(salt,0,4));
          state.salt32[1] = U8TO32_BE(Arrays.copyOfRange(salt,4,4));
          state.salt32[2] = U8TO32_BE(Arrays.copyOfRange(salt,8,4));
          state.salt32[3] = U8TO32_BE(Arrays.copyOfRange(salt,12,4));
        }
        else {
          state.salt64[0] = U8TO64_BE(Arrays.copyOfRange(salt,0,8));
          state.salt64[1] = U8TO64_BE(Arrays.copyOfRange(salt,8,8));
          state.salt64[2] = U8TO64_BE(Arrays.copyOfRange(salt,16,8));
          state.salt64[3] = U8TO64_BE(Arrays.copyOfRange(salt,24,8));
        }

        return SUCCESS;
      }
    
    private int Update32(short[] data, long databitlen ) {


        long fill;
        long left; /* to handle data inputs of up to 2^64-1 bits */
        
        if ( ( databitlen == 0 ) && (state.datalen != 512 ) )
          return SUCCESS;

        left = (state.datalen >> 3); 
        fill = 64 - left;

        /* compress remaining data filled with new bits */
        if( left !=0 && ( ((databitlen >> 3) & 0x3F) >= fill ) ) {
         // memcpy( (void *) (state->data32 + left),
         //     (void *) data, fill );
            System.arraycopy(data, 0, state.data32, (int)left, (int)(fill));
          /* update counter */
          state.t32[0] += 512;
          if (state.t32[0] == 0)
            state.t32[1]++;
            
          compress32(state.data32);
          //System.arraycopy(data, 0, data, (int)fill, data.length);
          databitlen  -= (fill << 3); 
            
          left = 0;
        }

        /* compress data until enough for a block */
        while( databitlen >= 512 ) {

          /* update counter */
          state.t32[0] += 512;

          if (state.t32[0] == 0)
            state.t32[1]++;
          compress32(data);
          //data += 64;
          System.arraycopy(data, 0, data, 8, data.length);
          databitlen  -= 512;
        }
        
        if( databitlen > 0 ) {
          //memcpy( (void *) (state->data32 + left),
          //    (void *) data, databitlen>>3 );
        	System.out.println(Arrays.toString(state.data32));
        	System.out.println(Long.toString(left));
            System.arraycopy(data, 0, state.data32, (int)(left), (int)databitlen>>3);
          state.datalen = (left<<3) + (int)databitlen;
          /* when non-8-multiple, add remaining bits (1 to 7)*/
          if ( (databitlen & 0x7) != 0)
            state.data32[(int) ((int)(left) + (databitlen>>3))] = data[(int) (databitlen>>3)];
        }
        else
          state.datalen=0;


        return SUCCESS;
      }

    private int Update64(short[] data, long databitlen ) {


        long fill;
        long left;

        if ( ( databitlen == 0 ) && (state.datalen != 1024 ) )
          return SUCCESS;

        left = (state.datalen >> 3);
        fill = 128L - left;

        /* compress remaining data filled with new bits */
        if( left!= 0 && ( ((databitlen >> 3) & 0x7F) >= fill ) ) {
          //memcpy( (void *) (state->data64 + left),
            //  (void *) data, fill );
            System.arraycopy(data, 0, state.data64, (int)left,(int)left + ((int)fill/8));
          /* update counter  */
         state.t64[0] += 1024;

         compress64(state.data64 );
         //data += fill;
         System.arraycopy(data, 0, data, (int)fill/8, data.length);
         databitlen  -= (fill << 3); 
            
          left = 0;
        }

        /* compress data until enough for a block */
        while( databitlen >= 1024 ) {
        
          /* update counter */
         state.t64[0] += 1024;
         compress64(data);
          //data += 128;
         System.arraycopy(data, 0, data, 16, data.length);
          databitlen  -= 1024;
        }

        if( databitlen > 0 ) {
          //memcpy( (void *) (state->data64 + left),
            //  (void *) data, ( databitlen>>3 ) & 0x7F );
            System.arraycopy(data, 0, state.data64, (int)left, (int)(databitlen>>3) & 0x7F);
          state.datalen = (int) ((left<<3) + databitlen);

          /* when non-8-multiple, add remaining bits (1 to 7)*/
          if ( (databitlen & 0x7) !=0 )
            state.data64[(int) (left + (databitlen>>3))] = data[(int) (databitlen>>3)];
        }
        else
          state.datalen=0;

        return SUCCESS;
      }
    
    private int Update(short[] data, int databitlen) {

        if ( state.hashbitlen < 384 )
          return Update32(data, databitlen );
        else
          return Update64(data, databitlen);
    }
    
    private int Final32() {
        short msglen[] = new short [8];
        short[] zz={(short)0x00};
        short[] zo={(short)0x01};
        short[] oz={(short)0x80};
        short[] oo={(short)0x81};

        /* 
           copy nb. bits hash in total as a 64-bit BE word
        */
        long low, high;
        low  = state.t32[0] + state.datalen;
        high = state.t32[1];
        if ( low < state.datalen )
          high++;
        System.out.println(Integer.toHexString((int)high));
        short[] msglen0 = U32TO8_BE((int)high);
        short[] msglen1 = U32TO8_BE((int)low);
        ShortBuffer msg = ShortBuffer.wrap(msglen);
        msg.put(msglen0);
        msg.put(msglen1);

        if ( state.datalen % 8 == 0) {
          /* message bitlength multiple of 8 */

          if ( state.datalen == 440 ) {
            /* special case of one padding short */
            state.t32[0] -= 8;
            if ( state.hashbitlen == 224 ) 
          Update32(oz, 8 );
            else
          Update32(oo, 8 );
          }
          else {
            if ( state.datalen < 440 ) {
          /* use t=0 if no remaining data */
          if ( state.datalen == 0 ) 
            state.nullt=1;
          /* enough space to fill the block  */
          state.t32[0] -= 440 - state.datalen;
          Update32(padding, 440 - state.datalen );
            }
            else {
          /* NOT enough space, need 2 compressions */
          state.t32[0] -= 512 - state.datalen;
          Update32(padding, 512 - state.datalen );
          state.t32[0] -= 440;
          Update32(Arrays.copyOfRange(padding,1,padding.length), 440 );  /* padd with zeroes */
          state.nullt = 1; /* raise flag to set t=0 at the next compress */
            }
            if ( state.hashbitlen == 224 ) 
          Update32(zz, 8 );
            else
          Update32(zo, 8 );
            state.t32[0] -= 8;
          }
          state.t32[0] -= 64;
          Update32(msglen, 64L );    
        }
        else {  
          /* message bitlength NOT multiple of 8 */

          /*  add '1' */
          state.data32[(int) (state.datalen/8)] &= (0xFF << (8-state.datalen%8)); 
          state.data32[(int) (state.datalen/8)] ^= (0x80 >> (state.datalen%8)); 

          if (( state.datalen > 440 ) && ( state.datalen < 447 )) {
            /*  special case of one padding short */
            if ( state.hashbitlen == 224 ) 
          state.data32[(int) (state.datalen/8)] ^= 0x00;
            else
          state.data32[(int) (state.datalen/8)] ^= 0x01;
            state.t32[0] -= (8 - (state.datalen%8));
            /* set datalen to a 8 multiple */
            state.datalen = (state.datalen&0xfffffffffffffff8L)+8;
          }
          else { 
            if (state.datalen < 440) {
          /* enough space to fill the block */
          state.t32[0] -= 440 - state.datalen;
          state.datalen = (state.datalen&0xfffffffffffffff8L)+8;
          Update(Arrays.copyOfRange(padding,1,padding.length), (int)(440 - state.datalen) );
            }
            else { 
          if (state.datalen > 504 ) {
            /* special case */
            state.t32[0] -= 512 - state.datalen;
            state.datalen=512;
            Update32(Arrays.copyOfRange(padding,1,padding.length), 0 );
            state.t32[0] -= 440;
            Update32(Arrays.copyOfRange(padding,1,padding.length), 440 );
            state.nullt = 1; /* raise flag for t=0 at the next compress */
          }
          else {
            /* NOT enough space, need 2 compressions */
            state.t32[0] -= 512 - state.datalen;
            /* set datalen to a 8 multiple */
            state.datalen = (state.datalen&0xfffffffffffffff8L)+8;
            Update32(Arrays.copyOfRange(padding,1,padding.length), 512 - state.datalen );
            state.t32[0] -= 440;
            Update32(Arrays.copyOfRange(padding,1,padding.length), 440 );
            state.nullt = 1; /* raise flag for t=0 at the next compress */
          }
            }
            state.t32[0] -= 8;
            if ( state.hashbitlen == 224 ) 
          Update32(zz, 8 );
            else
          Update32(zo, 8 );
          }
          state.t32[0] -= 64;
          Update32(msglen, 64L ); 
        }

        short[] hashval0 = U32TO8_BE(state.h32[0]);
        short[] hashval1 = U32TO8_BE(state.h32[1]);
        short[] hashval2 = U32TO8_BE(state.h32[2]);
        short[] hashval3 = U32TO8_BE(state.h32[3]);
        short[] hashval4 = U32TO8_BE(state.h32[4]);
        short[] hashval5 = U32TO8_BE(state.h32[5]);
        short[] hashval6 = U32TO8_BE(state.h32[6]);
        
        ShortBuffer target = ShortBuffer.wrap(hashval);
        target.put(hashval0);
        target.put(hashval1);
        target.put(hashval2);
        target.put(hashval3);
        target.put(hashval4);
        target.put(hashval5);
        target.put(hashval6);

        if ( state.hashbitlen == 256 ) {
          short[] hashval7 = U32TO8_BE(state.h32[7]);
          target.put(hashval7);
        }
        
        return SUCCESS;
    }
    
    private int Final64() {


        short msglen[] = {0,0};
        //int zz=0x00,zo=0x01,oz=0x80,oo=0x81;
        short[] zz={0x0,0x0};
        short[] zo={0x0,0x1};
        short[] oz={0x8,0x0};
        short[] oo={0x8,0x1};
        
        /* copy nb. bits hash in total as a 128-bit BE word */
        long low, high;
        low  = state.t64[0] + state.datalen;
        high = state.t64[1];
        if ( low < state.datalen )
          high = high + 1;
        short[] msglen0 = U64TO8_BE(high);
        short[] msglen1 = U64TO8_BE(low);
        ShortBuffer msg = ShortBuffer.wrap(msglen);
        msg.put(msglen0);
        msg.put(msglen1);

        if ( state.datalen % 8 == 0) {
          /* message bitlength multiple of 8 */

          if ( state.datalen == 888 ) {
            /* special case of one padding short */
            state.t64[0] -= 8; 
            if ( state.hashbitlen == 384 ) 
          Update64(oz, 8 );
            else
          Update64(oo, 8 );
          }
          else {
            if ( state.datalen < 888 ) {
          /* use t=0 if no remaining data */
          if ( state.datalen == 0 ) 
            state.nullt=1;
          /* enough space to fill the block */
          state.t64[0] -= 888 - state.datalen;
          Update64(padding, 888 - state.datalen );
            }
            else { 
          /* NOT enough space, need 2 compressions */
          state.t64[0] -= 1024 - state.datalen; 
          Update64(padding, 1024 - state.datalen );
          state.t64[0] -= 888;
          Update64(Arrays.copyOfRange(padding,1,padding.length), 888 );  /* padd with zeros */
          state.nullt = 1; /* raise flag to set t=0 at the next compress */
            }
            if ( state.hashbitlen == 384 ) 
          Update64(zz, 8 );
            else
          Update(zo, 8 );
            state.t64[0] -= 8;
          }
          state.t64[0] -= 128;
          Update(msglen, 128 );    
        }
        else {  
          /* message bitlength NOT multiple of 8 */

          /* add '1' */
          state.data64[(int) (state.datalen/8)] &= (0xFF << (8-state.datalen%8)); 
          state.data64[(int) (state.datalen/8)] ^= (0x80 >> (state.datalen%8)); 

          if (( state.datalen > 888 ) && ( state.datalen < 895 )) {
            /*  special case of one padding short */
            if ( state.hashbitlen == 384 ) 
          state.data64[(int) (state.datalen/8)] ^= 0x00;
            else
          state.data64[(int) (state.datalen/8)] ^= 0x01;
            state.t64[0] -= (8 - (state.datalen%8));
            /* set datalen to a 8 multiple */
            state.datalen = (state.datalen&0xfffffffffffffff8L)+8;
          }
          else { 
            if (state.datalen < 888) {
          /* enough space to fill the block */
          state.t64[0] -= 888 - state.datalen;
          state.datalen = (state.datalen&0xfffffffffffffff8L)+8;
          Update64(Arrays.copyOfRange(padding,1,padding.length), 888 - state.datalen );
            }
            else {
          if (state.datalen > 1016 ) {
            /* special case */
            state.t64[0] -= 1024 - state.datalen;
            state.datalen=1024;
            Update64(Arrays.copyOfRange(padding,1,padding.length), 0 );
            state.t64[0] -= 888;
            Update64(Arrays.copyOfRange(padding,1,padding.length), 888 );
            state.nullt = 1; /* raise flag for t=0 at the next compress */
          }
          else {
            /* NOT enough space, need 2 compressions */
            state.t64[0] -= 1024 - state.datalen;
            /* set datalen to a 8 multiple */
            state.datalen = (state.datalen&0xfffffffffffffff8L)+8;
            Update64(Arrays.copyOfRange(padding,1,padding.length), 1024 - state.datalen );
            state.t64[0] -= 888;
            Update64(Arrays.copyOfRange(padding,1,padding.length), 888 );
            state.nullt = 1; /* raise flag for t=0 at the next compress */
          }
            }
            state.t64[0] -= 8;
            if ( state.hashbitlen == 384 ) 
          Update64(zz, 8 );
            else
          Update64(zo, 8 );
          }
          state.t64[0] -= 128;
          Update(msglen, 128 ); 
        }

        short[] hashval0 = U64TO8_BE(state.h64[0]);
        short[] hashval1 = U64TO8_BE(state.h64[1]);
        short[] hashval2 = U64TO8_BE(state.h64[2]);
        short[] hashval3 = U64TO8_BE(state.h64[3]);
        short[] hashval4 = U64TO8_BE(state.h64[4]);
        short[] hashval5 = U64TO8_BE(state.h64[5]);
        
        ShortBuffer target = ShortBuffer.wrap(hashval);
        target.put(hashval0);
        target.put(hashval1);
        target.put(hashval2);
        target.put(hashval3);
        target.put(hashval4);
        target.put(hashval5);
        
        if ( state.hashbitlen == 512 ) {
        	short[] hashval6 = U64TO8_BE(state.h64[6]);
        	short[] hashval7 = U64TO8_BE(state.h64[7]);
        	target.put(hashval6);
            target.put(hashval7);
        }
        
        return SUCCESS;
      }
    
    private int Final(){
        if (state.hashbitlen < 384 )
            return Final32();
        else
           return Final64();
    }
    
    private int Hash(int hashbitlen,short[] data, int databitlen){
        int ret;
        System.out.println(hashbitlen);
        ret = Init(hashbitlen);
        if ( ret != SUCCESS ){
        	System.out.println("Init");
        	return ret;
        }
        
        ret = Update(data, databitlen);
        if ( ret != SUCCESS ){
        	System.out.println("Update");
        	return ret;
        }

        ret = Final();
        System.out.println("Final!");
       return ret;
    }
    
    private static int U8TO32_BE(short[] p){
	    int q = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
	    //System.out.println(Integer.toHexString(p[0]));
	    //System.out.println(Integer.toHexString(p[1]));
	    //System.out.println(Integer.toHexString(p[1] << 16));
	       return q; }	    
    private static long U8TO64_BE(short[] p){
	 	long q = ((long)(p[0]) << 56) | ((long)p[1] << 48) | ((long)p[2] << 40) | ((long)p[3] << 32) | 
    			((long)p[4] << 24) | ((long)p[5] << 16) | ((long)p[6] << 8) | (long)p[7];
	        return q;
	    }
    private static short[] U32TO8_BE(int v){
	    String test;
	    test = String.format("%08X", v);
	    System.out.println(test);
    	short [] p=new short[4];
    	p[0] = Short.parseShort(test.substring(0, 2), 16);
    	p[1] = Short.parseShort(test.substring(2, 4), 16);
    	p[2] = Short.parseShort(test.substring(4, 6), 16);
    	p[3] = Short.parseShort(test.substring(6, 8), 16);
    	//p[0]=(short)((v)>>24);
        //p[1]=(short)((v)>>16);
        //p[2]=(short)((v)>>8);
        //p[3]=(short)((v));
        //System.out.println(p[1]);
    	return p;
    }
 
    private static short[] U64TO8_BE(long v){ 
    	short [] p1=U32TO8_BE((int)((v) >> 32));	
    	short [] p2=U32TO8_BE((int)((v)));
    	short [] p3=new short[8];
    	for(int i=0; i<4; i++) {
    		Arrays.fill(p3, i, i+1, p1[i]);
    		Arrays.fill(p3, i+4, i+5, p2[i]);
    	}
    	return p3;  
    }
}
