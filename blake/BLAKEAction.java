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

	public byte[] run(int hashlength, String str) {
        BLAKEAlgorithm e = new BLAKEAlgorithm(hashlength, str.getBytes());
        return e.getHash();
    }

    public byte[] run(int hashlength, String str, String salt) {
        BLAKEAlgorithm e = new BLAKEAlgorithm(hashlength, str.getBytes(), salt);
        return e.getHash();
    }
}
