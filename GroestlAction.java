package org.jcryptool.crypto.modern.sha3.groestl;

/**
 * The action class of GROESTL.
 *
 * @author Zixun Yuan
 *
 */
public class GroestlAction {

    public byte[] run(int hashlength, String str) {
    	GroestlAlgorithm g = new GroestlAlgorithm(hashlength, str.getBytes());        
		byte[] bytes = g.getHash();
		return bytes;
    }
}