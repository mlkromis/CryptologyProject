package org.jcryptool.visual.sha3candidates.algorithms.BLAKE;
// -----BEGIN DISCLAIMER-----
/*******************************************************************************
 * Copyright (c) 2010 JCrypTool team and contributors
 *
 * All rights reserved. This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *******************************************************************************/
// -----END DISCLAIMER-----


/**
 * The action class of ECHO.
 *
 * @author Daniel Finn
 *
 */



public class Blake_Action {
	public byte[] run(int hashlength, String str) {
        Blake_Algorithm e = new Blake_Algorithm(hashlength, str.getBytes());
        return e.getHash();
    }

    public byte[] run(int hashlength, String str, String salt) {
        Blake_Algorithm e = new Blake_Algorithm(hashlength, str.getBytes(),salt);
        return e.getHash();
    }
}
