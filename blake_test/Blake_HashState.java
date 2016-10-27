package blake;

public class Blake_HashState {
	public short hashbitlen;
    public long datalen;
    public short init;
    public short nullt;
    public int h32[];
    public int t32[];
    public short[] data32;
    public int salt32[];
    public long h64[];
    public long t64[];
    public short[] data64;
    public long salt64[];
   /* u32 h32[8];         /* current chain value (initialized to the IV) */
  /*  u32 t32[2];         /* number of bits hashed so far */
    /*BitSequence data32[64];     /* remaining data to hash (less than a block) */
    /*u32 salt32[4];      /* salt (null by default) */
    /*
      variables for the 64-bit version  
    */
   /* u64 h64[8];      /* current chain value (initialized to the IV) */
   /* u64 t64[2];      /* number of bits hashed so far */
  /*  BitSequence data64[128];  /* remaining data to hash (less than a block) */
  /*  u64 salt64[4];   /* salt (null by default) */
    
    Blake_HashState() {
        this.h32 = new int[8];
        this.t32 = new int[2];
        this.data32 = new short[64];
        this.salt32 = new int[4];
        this.h64 = new long[8];
        this.t64 = new long[2];
        this.data64 = new short[128];
        this.salt64 = new long[4];
    }
}
