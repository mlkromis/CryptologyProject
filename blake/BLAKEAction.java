package org.jcryptool.crypto.modern.sha3.blake;

/**
 * The action class of BLAKE.
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