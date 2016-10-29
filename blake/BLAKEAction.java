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

/**
 * The action class of ECHO.
 *
 * @author Daniel Finn
 *
 */

import java.util.Arrays;

public class BLAKEAction {
	/*public static void main(String[] args) {
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
		
	}*/
	public byte[] run(int hashlength, String str) {
        BLAKEAlgorithm e = new BLAKEAlgorithm(hashlength, str.getBytes());
        return e.getHash();
    }

    public byte[] run(int hashlength, String str, String salt) {
        BLAKEAlgorithm e = new BLAKEAlgorithm(hashlength, str.getBytes(), salt);
        return e.getHash();
    }
}
