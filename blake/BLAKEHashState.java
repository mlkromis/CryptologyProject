// -----BEGIN DISCLAIMER-----
/*******************************************************************************
 * Copyright (c) 2010 JCrypTool team and contributors
 *
 * All rights reserved. This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *******************************************************************************/
// -----END DISCLAIMER-----

package blake;

public class BLAKEHashState {
    public short hashbitlen;
    public int datalen;
    public short init;
    public short nullt;
    public int h32[];
    public int t32[];
    public byte[] data32;
    public int salt32[];
    public long h64[];
    public long t64[];
    public byte[] data64;
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
}
