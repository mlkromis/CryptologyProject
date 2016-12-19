
package org.jcryptool.crypto.modern.sha3.groestl;

/**
 *
 * @author Zixun Yuan
 */
public class GroestlHashState {
	public byte[][] chaining;
	public long block_counter;
	public int hashbitlen;
	public byte[] buffer;
	public int buf_ptr;
	public int bits_in_last_byte;
	public int columns;
	public int rounds;
	public int statesize;
	
	public GroestlHashState() {
		this.chaining = new byte[8][16];
		this.buffer = new byte[128];
	}
}