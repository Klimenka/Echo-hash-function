package domain.proof.hashing.echo;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * For this algorithm official documentation from
 * https://csrc.nist.gov/projects/hash-functions/sha-3-project padding was made
 * using test results of ECHO for round 2 of SHA-3 the link for this documents:
 * https://web.archive.org/web/20170221021140if_/http://csrc.nist.gov/groups/ST/hash/sha-3/Round2/documents/ECHO_Round2.zip
 * 
 * @author n klimenko
 *
 */
public class Logic {

	static byte[] Ci = new byte[16];

	/**
	 * A padding rule will be applied to the message M input to ECHO and this
	 * guarantees that the padded message M' has a length n that is a multiple of
	 * 128. The part of this method was taken from SHA512 class of this program.
	 */
	public static byte[] pad(byte[] input) {
		/*
		 * the length of the array will be created here. We need: 1) message length
		 * (bits) 2) 1 bit 3) n zeros 4) 16 bits for Hsize 5) 128 for bit representation
		 * of the length of the message
		 */
		
		// +18 because we need 145 bits = 18 bytes
		int size = input.length + 18;
		while (size % 128 != 0) {
			size += 1;
		}

		// The padded byte array
		byte[] out = new byte[size];

		// First step is to place a message itself to this array
		for (int i = 0; i < input.length; i++) {
			out[i] = (byte) (input[i] & 0xff);
		}

		// Add the '1' bit after the message
		out[input.length] = (byte) 0x80;

		// Now we need 16 bits for Hsize = 512 bits.
		// A bit string in hexadecimal notation "0x0002"
		// make sure that we left 16 last bytes for the L of 128 bits
		out[out.length - 16 - 2] = (byte) 0x00;
		out[out.length - 16 - 1] = (byte) 0x02;

		// Somewhat legacy code, was using BigInteger before converting to longs, but it
		// works
		// so why change it
		// Convert the original length of the input to a byte array
		byte[] lenInBytes = BigInteger.valueOf(input.length * 8).toByteArray();

		int indexPlaceForSize = 17;
		// And put it at the end of our padded input (this place was taken from official
		// documentation of ECH0 and test output of ECHO algorithm)
		for (int i = lenInBytes.length; i > 0; i--) {
			out[size + i - indexPlaceForSize] = (byte) (lenInBytes[lenInBytes.length - i] & 0xff);

		}
		// initialize Ci (will be needed later for creation of the first key)
		Ci = Arrays.copyOfRange(out, size - indexPlaceForSize + 1, size);

		// Print out the total message bits before/after if debug >= 1
		if (Echo.DEBUG >= 1) {
			System.out.printf("Total message length in bits before padding: %d\n", input.length * 8);
			System.out.printf("Total message length in bits after padding: %d\n", out.length * 8);
		}

		return out;
	}

	/**
	 * Converts the byte array input starting at index j into a word
	 *(notation from the description of the algorithm)
	 * @param input byte[]
	 * @param j (index)
	 * @return
	 */
	public static byte[] arrToWord(byte[] input, int j) {
		byte[] word = new byte[16];
		int index = 0;
		for (int i = 0; i < 16; i++) {
			word[index] = (byte) (input[i + j] & 0xff);
			index++;
		}
		return word;
	}

	/** Converts the byte array input into blocks of 8x(4x4) byte array
	 * 
	 * @param input
	 * @return byte[][][][]
	 */
	public static byte[][][][] toBlocks(byte[] input) {

		// a block has: 1024 bits = 128 bytes = 8 cells of 4x4 bytes (16 bytes for each
		// cell)
		byte[][][][] blocks = new byte[input.length / 128][8][4][4];

		// For every block
		for (int i = 0; i < input.length / 128; i++) {
			// For each long in a block
			for (int j = 0; j < 8; j++) {
				// Set the block value to the correct one
				blocks[i][j] = copyTwoDimentionalArray(make4x4BoxFromWord(arrToWord(input, i * 128 + j * 16)));
			}
		}
		return blocks;
	}

	/**
	 * sometimes we need to manipulate with 16 bytes as 4x4 boxes and sometimes just
	 * as an array.
	 * this method convert simple byte [16] into byte[4][4]
	 * @param byte[] word
	 * @return byte[][]
	 */
	public static byte[][] make4x4BoxFromWord(byte[] word) {
		byte[][] newWord = new byte[4][4];
		int index = 0;
		for (int c = 0; c < 4; c++) {
			for (int r = 0; r < 4; r++) {
				newWord[r][c] = word[index];
				index++;
			}
		}
		return newWord;
	}

	/**
	 * sometimes we need to manipulate with 16 bytes as 4x4 boxes and sometimes just
	 * as an array.
	 * this method convert byte[4][4] into simple byte [16]
	 * @param wordBox[4][4]
	 * @return
	 */
	public static byte[] return4x4BoxToArray(byte[][] wordBox) {
		byte[] line = new byte[16];
		int index = 0;
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				line[index] = wordBox[i][j];
				index++;
			}
		}
		return line;
	}

	/**
	 * the most important part of the ECHO algorithm. This method produces a chaining
	 * variable for hashing process.
	 * @param V
	 * @param block
	 * @return
	 */
	public static byte[][][] compress1024(byte[][][] V, byte[][][] block) {

		// first step is to create a message block S from V and block itself
		byte[][][][] S = makeAMessageBlockS(V, block);
		// for created message block we will call 10 rounds of Big.Round and 1 time
		// Big.Final
		for (int i = 0; i < 10; i++) {
			subWords(S, Constants.SALT, Ci);
			shiftRows(S);
			mixColumns(S);
		}
		byte[][] finalV = bigFinal(S, V, block);

		// to make byte[8][4][4] from byte[8][16]
		return makeFinalVBox(finalV);
	}

	/**
	 * v0 v4 m0 m4 
	 * v1 v5 m1 m5 
	 * v2 v6 m2 m6 
	 * v3 v7 m3 m7
	 * 
	 * every cell called word (notation from the description of ECHO and every cell
	 * consists of 4x4 array because we need this structure to shift rows and mix
	 * columns of each word
	 */
	public static byte[][][][] makeAMessageBlockS(byte[][][] V, byte[][][] block) {
		byte[][][][] messageBlockS = new byte[4][4][4][4];
		messageBlockS[0][0] = copyTwoDimentionalArray(V[0]);
		messageBlockS[1][0] = copyTwoDimentionalArray(V[1]);
		messageBlockS[2][0] = copyTwoDimentionalArray(V[2]);
		messageBlockS[3][0] = copyTwoDimentionalArray(V[3]);

		messageBlockS[0][1] = copyTwoDimentionalArray(V[4]);
		messageBlockS[1][1] = copyTwoDimentionalArray(V[5]);
		messageBlockS[2][1] = copyTwoDimentionalArray(V[6]);
		messageBlockS[3][1] = copyTwoDimentionalArray(V[7]);

		messageBlockS[0][2] = copyTwoDimentionalArray(block[0]);
		messageBlockS[1][2] = copyTwoDimentionalArray(block[1]);
		messageBlockS[2][2] = copyTwoDimentionalArray(block[2]);
		messageBlockS[3][2] = copyTwoDimentionalArray(block[3]);

		messageBlockS[0][3] = copyTwoDimentionalArray(block[4]);
		messageBlockS[1][3] = copyTwoDimentionalArray(block[5]);
		messageBlockS[2][3] = copyTwoDimentionalArray(block[5]);
		messageBlockS[3][3] = copyTwoDimentionalArray(block[5]);

		return messageBlockS;
	}

	/**
	 * This method calls AES rounds for every word in S array.
	 * k = Ci initially.
	 * @param S
	 * @param SALT
	 * @param k
	 */
	public static void subWords(byte[][][][] S, byte[] SALT, byte[] k) {
		byte[] k1 = k;
		byte[] k2 = SALT;
		for (byte[][][] row : S) {
			for (byte[][] w : row) {
				// do 2 rounds of original AES for every word in S
				w = aes(aes(w, k1), k2);
				// after each AES level we do + 1 to the key and related Ci also changed
				// so the next level starts with Ci + 16 (because we have 16 words)
				k1[0] = (byte) (k1[0] + 1);
			}
		}
	}

	/**
	 * This method calls 4 methods of AES process SubByte(a); ShiftRows(a);
	 * MixColumns(a); AddRoundKey(a,k)
	 * 
	 */
	public static byte[][] aes(byte[][] w, byte[] k) {
		aesSubBytes(w);
		aesShiftRows(w);
		aesMixColumns(w);
		aesaddRoundKey(w, k);
		return w;
	}

	/**
	 * Replaces all elements in the passed array [4][4] with values in Constants.sbox[][].
	 * 
	 */
	public static void aesSubBytes(byte[][] arr) {

		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				int hex = (arr[i][j] & 0xFF);
				arr[i][j] = (byte) Constants.sbox[hex / 16][hex % 16];
			}
		}
	}

	/**
	 * shift rows like: first row no shift, second row three position right shift,
	 * third row two position right shift, last row one position right shift
	 * 
	 */
	public static void aesShiftRows(byte[][] w) {
		byte[] tmp = new byte[4];
		int i, j;
		for (i = 1; i < 4; i++) {
			for (j = 0; j < 4; j++)
				tmp[j] = w[i][(j + i) % 4];
			for (j = 0; j < 4; j++)
				w[i][j] = tmp[j];
		}
	}

	/**
	 * MixColumn method which uses the GF(2^8)
	 */
	private static void aesMixColumns(byte[][] w) {
		byte[][] temp = new byte[4][4];
		for (int c = 0; c < 4; c++) {
			temp[0][c] = (byte) (GMul((byte) 0x02, w[0][c]) ^ GMul((byte) 0x03, w[1][c]) ^ w[2][c] ^ w[3][c]);
			temp[1][c] = (byte) (w[0][c] ^ GMul((byte) 0x02, w[1][c]) ^ GMul((byte) 0x03, w[2][c]) ^ w[3][c]);
			temp[2][c] = (byte) (w[0][c] ^ w[1][c] ^ GMul((byte) 0x02, w[2][c]) ^ GMul((byte) 0x03, w[3][c]));
			temp[3][c] = (byte) (GMul((byte) 0x03, w[0][c]) ^ w[1][c] ^ w[2][c] ^ GMul((byte) 0x02, w[3][c]));
		}

		w = copyTwoDimentionalArray(temp);
	}

	/**
	 * Galois Field (256) Multiplication of two Bytes
	 * @param a
	 * @param b
	 * @return
	 */
	private static byte GMul(byte a, byte b) {
		byte p = 0;

		for (int i = 0; i < 8; i++) {
			if ((b & 1) != 0) {
				p ^= a;
			}

			Boolean hi_bit = (a & 0x80) != 0;
			a <<= 1;
			if (hi_bit) {
				// x^8 + x^4 + x^3 + x + 1
				a ^= 0x1B;
			}
			b >>= 1;
		}

		return p;
	}

	/**
	 * Bit wise XOR for a key and a word
	 */
	public static void aesaddRoundKey(byte[][] w, byte[] k) {
		byte[][] key4x4 = copyTwoDimentionalArray(make4x4BoxFromWord(k));

		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				w[i][j] ^= key4x4[i][j];
			}
		}
	}
	
	/**
	 * Shift rows for the whole S message box in the same way as for aes round
	 */
	public static void shiftRows(byte[][][][] S) {
		// r=0 is not shifted
		byte[][][] tmp = new byte[4][4][4];
		int i, j;
		for (i = 1; i < 4; i++) {
			for (j = 0; j < 4; j++)
				tmp[j] = copyTwoDimentionalArray(S[i][(j + i) % 4]);
			for (j = 0; j < 4; j++)
				S[i][j] = copyTwoDimentionalArray(tmp[j]);
		}
	}
	/**
	 *  Mix columns for the whole S message box in the same way as for aes round
	 * @param S
	 */
	public static void mixColumns(byte[][][][] S) {
		int i, j, k;
		for (i = 0; i < 4; i++) {
			for (j = 0; j < 4; j++) {
				for (k = 0; k < 4; k++) {
					mix4Bytes(S[0][i][j][k], S[1][i][j][k], S[2][i][j][k], S[3][i][j][k]);
				}
			}
		}
	}

	/**
	 * Supporting method for mix columns for 4 bytes
	 * @param a
	 * @param b
	 * @param c
	 * @param d
	 */
	public static void mix4Bytes(byte a, byte b, byte c, byte d) {
		/* Mix four bytes in a linear way */
		byte aa, bb, cc, dd;

		aa = (byte) (GMul((byte) 2, a) ^ GMul((byte) 3, b) ^ (c) ^ (d));
		bb = (byte) (GMul((byte) 2, b) ^ GMul((byte) 3, c) ^ (d) ^ (a));
		cc = (byte) (GMul((byte) 2, c) ^ GMul((byte) 3, d) ^ (a) ^ (b));
		dd = (byte) (GMul((byte) 2, d) ^ GMul((byte) 3, a) ^ (b) ^ (c));
		a = aa;
		b = bb;
		c = cc;
		d = dd;
	}

	/**
	 * Big Final method does XOR between S message box, original block and V.
	 * 
	 * @param S
	 * @param V
	 * @param block
	 * @return byte [8][16]
	 */
	public static byte[][] bigFinal(byte[][][][] S, byte[][][] V, byte[][][] block) {
		byte[][] finalBox = new byte[8][16];

		// for indexes for S
		int j = 0;
		int l = 2;
		for (int i = 0; i < 8; i++) {
			if (i > 3) {
				j = 1;
				l = 3;
			}
			byte[] a = return4x4BoxToArray(V[i]);
			byte[] b = return4x4BoxToArray(block[i]);
			byte[] c = return4x4BoxToArray(S[i % 4][j]);
			byte[] d = return4x4BoxToArray(S[i % 4][l]);
			byte[] firstXOR = doXORForArrays(a, b);
			byte[] secondXOR = doXORForArrays(firstXOR, c);
			finalBox[i] = doXORForArrays(secondXOR, d);

		}
		return finalBox;
	}
	
	/**
	 * Method helper to do XOR for two byte arrays
	 * @param a
	 * @param b
	 * @return
	 */
	public static byte[] doXORForArrays(byte[] a, byte[] b) {
		byte[] c = new byte[a.length];
		for (int i = 0; i < a.length; i++) {

			c[i] = (byte) (a[i] ^ b[i]);
		}
		return c;
	}

	/**
	 * This method converts byte[8][16] to [8][4][4] needed for the next round
	 * @param V
	 * @return
	 */
	public static byte[][][] makeFinalVBox(byte[][] V) {
		byte[][][] VFinal = new byte[8][4][4];
		for (int i = 0; i < 8; i++) {
			VFinal[i] = make4x4BoxFromWord(V[i]);
		}
		return VFinal;

	}

	/**
	 * Method helper to copy two dimensional arrays
	 * @param a
	 * @return
	 */

	public static byte[][] copyTwoDimentionalArray(byte[][] a) {
		byte[][] newArray = new byte[a.length][a[0].length];
		for (int i = 0; i < a.length; i++) {
			for (int j = 0; j < a[0].length; j++) {
				newArray[i][j] = a[i][j];
			}
		}
		return newArray;
	}
	
	/**
	 * For the output string of hashing process only 4 first bytes needed
	 * So, this method converts V[8][4][4] into hex string of 512 bits
	 * @param V
	 * @return
	 */
	public static String forOutputStringFromV(byte[][][] V) {
		byte[][] output = new byte[4][16];
		byte[] temp = new byte[64];
		int index = 0;

		// we don't need all 8 cells, just 4 first cells for HSize 512
		for (int i = 0; i < 4; i++) {
			output[i] = return4x4BoxToArray(V[i]);
		}
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 16; j++) {
				temp[index] = output[i][j];
				index++;
			}
		}
		StringBuilder sb = new StringBuilder();
		for (byte b : temp) {
			sb.append(String.format("%02X", b));
		}

		return sb.toString();

	}
}
