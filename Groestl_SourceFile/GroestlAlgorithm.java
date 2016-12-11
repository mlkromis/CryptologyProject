
package org.jcryptool.crypto.modern.sha3.groestl;

import java.util.Arrays;

/**
 *
 * @author Zixun Yuan
 */
public class GroestlAlgorithm {
	private int SUCCESS=0;
    private int FAIL=1;
    private int BAD_HASHLEN=2;

    private GroestlHashState state;
    private byte[] hashval;
    private int status;
    
    private int ROWS = 8;
	
	private final int[] SInt = new int[] {
				0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
				0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
				0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
				0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
				0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
				0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
				0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
				0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
				0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
				0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
				0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
				0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
				0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
				0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
				0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
				0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
				0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
				0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
				0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
				0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
				0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
				0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
				0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
				0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
				0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
				0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
				0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
				0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
				0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
				0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
				0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
				0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
			};
	private byte[] S;
	
	private int[][][] Shift = new int[][][]{
		{{0,1,2,3,4,5,6,7}, {1,3,5,7,0,2,4,6}},
		{{0,1,2,3,4,5,6,11}, {1,3,5,11,0,2,4,6}}
	};
	
	//AddRoundConstant xors a round-dependent constant to the state
	private void AddRoundConstant(byte[][] x, int columns, int round, int v) {
		switch(v & 1) {
		case 0:
			for(int i = 0; i < columns; i++)
				x[0][i] ^= (i<<4)^round;
			break;
		case 1:
			for(int i = 0; i < columns; i++) {
				for(int j = 0; j < ROWS-1; j++) {
					x[j][i] ^= 0xff;
				}
			}
			for(int i = 0; i < columns; i++)
				x[ROWS-1][i] ^= (i<<4)^0xff^round;
			break;
		}
	}
	
	//ShiftBytes cyclically shifts each row to the left by a number of positions
	private void SubBytes(byte[][] x, int columns) {
		for(int i = 0; i < ROWS; i++) {
			for(int j = 0; j < columns; j++) {
				x[i][j] = S[(int)(x[i][j]&0xFF)];
			}
		}
	}
	
	//ShiftBytes cyclically shifts each row to the left by a number of positions
	private void ShiftBytes(byte[][] x, int columns, int v) {
		int[] R = Shift[v/2][v&1];
		byte[] temp = new byte[16];
		
		for(int i = 0; i < ROWS; i++) {
			for(int j = 0; j < columns; j++) {
				temp[j] = x[i][(j+R[i])%columns];
			}
			for(int j = 0; j < columns; j++) {
				x[i][j] = temp[j];
			}
		}
	}
	
	//MixBytes reversibly mixes the bytes within a column
	private void MixBytes(byte[][] x, int columns) {
		byte[] temp = new byte[ROWS];
		for(int i = 0; i < columns; i++) {
			for(int j = 0; j < ROWS; j++) {
				temp[j] = (byte) (mul2(x[(j+0)%ROWS][i])^
						  mul2(x[(j+1)%ROWS][i])^
						  mul3(x[(j+2)%ROWS][i])^
						  mul4(x[(j+3)%ROWS][i])^
						  mul5(x[(j+4)%ROWS][i])^
						  mul3(x[(j+5)%ROWS][i])^
						  mul5(x[(j+6)%ROWS][i])^
						  mul7(x[(j+7)%ROWS][i]));
			}
			for(int j = 0; j < ROWS; j++) {
				x[j][i] = temp[j];
			}
		}		
	}
	
	//apply P-permutation to x
	private void P(GroestlHashState ctx, byte[][] x) {
		int v = (ctx.columns == 8) ? 0 : 2;
		for(int i = 0; i < ctx.rounds; i++) {
			AddRoundConstant(x, ctx.columns, i, v);
			SubBytes(x, ctx.columns);
			ShiftBytes(x, ctx.columns, v);
			MixBytes(x, ctx.columns);
		}
	}
	
	//apply Q-permutation to x
	private void Q(GroestlHashState ctx, byte[][] x) {
		int v = (ctx.columns == 8) ? 1 : 3;
		for(byte i = 0; i < ctx.rounds; i++) {
			AddRoundConstant(x, ctx.columns, i, v);
			SubBytes(x, ctx.columns);
			ShiftBytes(x, ctx.columns, v);
			MixBytes(x, ctx.columns);
		}
	}
	
	//digest (up to) msglen bytes
	private void Transform(GroestlHashState ctx, byte[] input, int msglen) {
		byte[][] temp1 = new byte[8][16], temp2 = new byte[8][16];		
		int[] data = new int[input.length];
		for(int i = 0; i < input.length; i++)
				data[i] = input[i];
		int cur = 0;
		
		//digest one message block at the time
		for(; msglen >= ctx.statesize; msglen -= ctx.statesize, cur += ctx.statesize) {
			//store message block (m) in temp2, and xor of chaining (h) and message block in temp1
			for(int i = 0; i < ROWS; i++) {
				for(int j = 0; j < ctx.columns; j++) {
					temp1[i][j] = (byte) (ctx.chaining[i][j] ^ data[cur+j*ROWS+i]);
					temp2[i][j] = (byte) data[cur+j*ROWS+i];
				}
			}
			
			//P(h+m)
			P(ctx, temp1);
			//Q(m)
			Q(ctx, temp2);
			
			//xor P(h+m) and Q(m) onto chaining, yielding P(h+m)+Q(m)+h
			for(int i = 0; i < ROWS; i++) {
				for(int j = 0; j < ctx.columns; j++) {
					ctx.chaining[i][j] ^= temp1[i][j]^temp2[i][j];
				}
			}
			
			//increment block counter
			ctx.block_counter++;
		}
	}
	
	//do output transformation, P(h)+h
	private void OutputTransformation(GroestlHashState ctx) {
		byte[][] temp = new byte[8][16];
		
		//store chaining ("h") in temp
		for(int i = 0; i < ROWS; i++) {
			for(int j = 0; j < ctx.columns; j++) {
				temp[i][j] = ctx.chaining[i][j];
			}
		}
		
		//compute P(temp) = P(h)
		P(ctx, temp);
		
		//feed chaining forward, yielding P(h)+h
		for(int i = 0; i < ROWS; i++) {
			for(int j = 0; j < ctx.columns; j++) {
				ctx.chaining[i][j] ^= temp[i][j];
			}
		}
	}
	
	//Initialize context
	private int Init(GroestlHashState ctx, int hashbitlen) {		
		if(hashbitlen <= 0 || (hashbitlen%8) != 0 || hashbitlen > 512)
			return BAD_HASHLEN;
		
		if(hashbitlen <= 256) {
			ctx.rounds = 10;
			ctx.columns = 8;
			ctx.statesize = 64;
		}
		else {
			ctx.rounds = 14;
			ctx.columns = 16;
			ctx.statesize = 128;
		}
		
		//zeroise chaining variable
		for(int i = 0; i < ROWS; i++) {
			for(int j = 0; j < ctx.columns; j++) {
				ctx.chaining[i][j] = 0;
			}
		}
		
		//store hashbitlen and set initial value
		ctx.hashbitlen = hashbitlen;
		for(int i = ROWS-4; i < ROWS; i++) {	//4 = sizeof(int)
			ctx.chaining[i][ctx.columns-1] = (byte)(hashbitlen>>(8*(7-i)));
			//System.out.println(ctx.chaining[i][ctx.columns-1]);
		}
		
		//initialise other variables
		ctx.buf_ptr = 0;
		ctx.block_counter = 0;
		ctx.bits_in_last_byte = 0;
		
		return SUCCESS;
	}
	
	private int Update(GroestlHashState ctx, byte[] input, int databitlen) {
		int index = 0;
		//no. of (full) bytes supplied
		int msglen = databitlen/8;
		//no. of additional bits
		int rem = databitlen%8;
		
		if(ctx.bits_in_last_byte != 0)
			return FAIL;
		
		//if the buffer contains data that still needs to be digested
		if(ctx.buf_ptr != 0)  {
			//copy data into buffer until buffer is full, or there is no more data
			for(index = 0; ctx.buf_ptr < ctx.statesize && index < msglen; index++, ctx.buf_ptr++) {
				ctx.buffer[ctx.buf_ptr] = input[index];
			}
		
			if(ctx.buf_ptr < ctx.statesize) {
				//this chunk of message does not fill the buffer
				if(rem != 0) {
					//if there are additional bits, add them to the buffer
					ctx.bits_in_last_byte = rem;
					ctx.buffer[ctx.buf_ptr++] = input[index];
				}
				
				return SUCCESS;
			}
			
			//the buffer is full, digest
			ctx.buf_ptr = 0;
			Transform(ctx, ctx.buffer, ctx.statesize);
		}
		
		//digest remainder of data modulo the block size
		Transform(ctx, Arrays.copyOfRange(input, index, input.length), msglen-index);
		index += ((msglen-index)/ctx.statesize)*ctx.statesize;
		
		//copy remaining data to buffer
		for(; index < msglen; index++, ctx.buf_ptr++) {
			ctx.buffer[ctx.buf_ptr] = input[index];
		}
		
		if(rem != 0) {
			ctx.bits_in_last_byte = rem;
			ctx.buffer[ctx.buf_ptr++] = input[index];
		}
		
		return SUCCESS;
	}
	
	private int Final(GroestlHashState ctx, byte[] output) {
		int hashbytelen = ctx.hashbitlen/8;
		
		//100... padding
		if(ctx.bits_in_last_byte != 0) {
			ctx.buffer[ctx.buf_ptr-1] &= ((1<<ctx.bits_in_last_byte)-1)<<(8-ctx.bits_in_last_byte);
			ctx.buffer[ctx.buf_ptr-1] ^= 0x1<<(7-ctx.bits_in_last_byte);
		}
		else {
			ctx.buffer[ctx.buf_ptr++] = (byte) 0x80;
		}
		
		if(ctx.buf_ptr > ctx.statesize-8) {
			//padding requires two blocks
			while(ctx.buf_ptr < ctx.statesize) {
				ctx.buffer[ctx.buf_ptr++] = 0;
			}
			Transform(ctx, ctx.buffer, ctx.statesize);
			ctx.buf_ptr = 0;
		}
		while(ctx.buf_ptr < ctx.statesize-8) {
			ctx.buffer[ctx.buf_ptr++] = 0;
		}
		
		//length padding
		ctx.block_counter++;
		ctx.buf_ptr = ctx.statesize;
		while(ctx.buf_ptr > ctx.statesize-8) {
			ctx.buffer[--ctx.buf_ptr] = (byte) ctx.block_counter;
			ctx.block_counter >>= 8;
		}
		
		//digest (last) padding block
		Transform(ctx, ctx.buffer, ctx.statesize);
		//output transformation
		OutputTransformation(ctx);
		
		//store hash output
		int i = 0, j = 0;
		for(i = ctx.statesize-hashbytelen; i < ctx.statesize; i++, j++) {
			output[j] = ctx.chaining[i%ROWS][i/ROWS];
		}
		
		//zeroise
		for(i = 0; i < ROWS; i++) {
			for(j = 0; j < ctx.columns; j++) {
				ctx.chaining[i][j] = 0;
			}
		}
		for(i = 0; i < ctx.statesize; i++) {
			ctx.buffer[i] = 0;
		}
		
		return SUCCESS;
	}
	
	public GroestlAlgorithm(int hashbitlen, byte[] data) {
		this.status = FAIL;
        this.hashval = new byte[hashbitlen/8];
        this.state = new GroestlHashState();
        
        S = new byte[SInt.length];
        for(int i = 0; i < SInt.length; i++) {
        	S[i] = (byte) SInt[i];
        }
        
        status = Hash(hashbitlen, data);
	}
	
	private int Hash(int hashbitlen, byte[] data) {
		int F = FAIL;
		GroestlHashState ctx = new GroestlHashState();
		
		//Initialize		
		F = Init(ctx, hashbitlen);
		if(F != SUCCESS)
			return F;
		
		//process message
		F = Update(ctx, data, data.length);	//data.length: databitlen
		if(F != SUCCESS)
			return F;
		
		return Final(ctx, this.hashval);
	}	
	
	public byte[] getHash() {
		return this.hashval;
	}
	
	private byte mul1(byte b) {
		return b;
	}
	private byte mul2(byte b) {
		return (byte) (((b>>7) != 0) ? (b<<1)^0x1b : b<<1);
	}
	private byte mul3(byte b) {
		return (byte) (mul2(b)^mul1(b));
	}
	private byte mul4(byte b) {
		return mul2(mul2(b));
	}
	private byte mul5(byte b) {
		return (byte) (mul4(b)^mul1(b));
	}
	private byte mul6(byte b) {
		return (byte) (mul4(b)^mul2(b));
	}
	private byte mul7(byte b) {
		return (byte) (mul4(b)^mul2(b)^mul1(b));
	}
}