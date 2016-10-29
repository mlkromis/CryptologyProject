package org.jcryptool.visual.sha3candidates.algorithms;

/**
 * 
 * @author Ferit Dogan
 * 
 */
public enum HashFunction {
	ECHO224("ECHO (224 bits)"), ECHO256("ECHO (256 bits)"), ECHO384("ECHO (384 bits)"), ECHO512("ECHO (512 bits)"), SHA256( //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
			"SHA-2 (256 bits)"), SHA512("SHA-2 (512 bits)"), RIPEMD160("RIPEMD-160 (160 bits)"), SHA3_224("SHA-3 (224 bits)"), SHA3_256("SHA-3 (256 bits)"), SHA3_384("SHA-3 (384 bits)"), SHA3_512("SHA-3 (512 bits)"), SKEIN_256("SKEIN-256 (256 bits)"), SKEIN_512("SKEIN-512 (512 bits)"), SKEIN_1024("SKEIN-1024 (1024 bits)"), SM3("SM3 (256 bits)"), TIGER("TIGER (192 bits)"), GOST3411("GOST3411 (256 bits)"), WHIRLPOOL("WHIRLPOOL (512 bits)"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$ //$NON-NLS-6$ //$NON-NLS-7$ //$NON-NLS-8$ //$NON-NLS-9$ //$NON-NLS-10$ //$NON-NLS-11$ //$NON-NLS-12$ //$NON-NLS-13$ //$NON-NLS-14$

	private final String hashFunctionName;

	private HashFunction(String name) {
		hashFunctionName = name;
	}

	public HashFunction getName(String name) {
		for (HashFunction h : values()) {
			if (h.hashFunctionName.compareToIgnoreCase(name) == 0) {
				HashFunction value = valueOf(h.name());
				return value;
			}
		}
		return null;
	}
}
