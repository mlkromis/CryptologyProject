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
    public long datalen;
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

    Blake_HashState() {
        this.h32 = new int[8];
        this.t32 = new int[2];
        this.data32 = new byte[64];
        this.salt32 = new int[4];
        this.h64 = new long[8];
        this.t64 = new long[2];
        this.data64 = new byte[128];
        this.salt64 = new long[4];
    }
}
