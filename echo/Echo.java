package domain.proof.hashing.echo;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import domain.proof.hashing.echo.Logic;

/**
 * This class is the definition of the hash function ECHO. To call it use
 * Echo.hash(). It returns 512 bits hashed string.
 * 
 * @author Klimenko
 *
 */
public class Echo {
	public static int DEBUG = 0;

	public static void main(String[] args) throws IOException {

		// If the user isn't using the program correctly, or they want help
		if (args.length < 1 || args[0].equals("help")) {
			System.err.println("Usage: Echo input.txt <debug level>");
			System.err.println("       Debug level description:");
			System.err.println("         0: No debugging - only the final hash is printed");
			System.err.println("         1: Minimal debugging - only the block hashes are printed");
			System.err.println("         2: Maximum debugging - W values and abcdefg for each round are printed");
			System.exit(-1);
		}

		// If they provide a debug value, set it
		if (args.length > 1) {
			DEBUG = Integer.parseInt(args[1]);
		}

		File inputFile = new File(args[0]);

		if (!inputFile.isFile()) {
			System.err.println("Input file '" + args[0] + "' does not exist!");
			System.exit(-2);
		}

		// Read the entire input file as UTF-8
		String input = new String(Files.readAllBytes(inputFile.toPath()), StandardCharsets.UTF_8);

		// A strange bug occurs on Windows since it adds a carriage return as well as a
		// newline
		// Thus we have to get rid of all carriage returns in the read input
		input = input.replaceAll("\r\n", "\n");

		// Do the hash
		System.out.println(input);
		String hashed = Echo.hash(input.getBytes());

		// Print it out
		System.out.println(hashed);
	}

	// Does the actual hash
	public static String hash(byte[] input) {
		// First pad the input to the correct length, adding the bits specified in the
		// ECHO algorithm
		input = Logic.pad(input);
		// Break the padded input up into blocks
		// [number of blocks][8][4][4]
		byte[][][][] blocks = Logic.toBlocks(input);
		// to save previous chaining variable
		byte[][][] V = new byte[8][4][4];
		// to save new chaining variable
		byte[][][] VNext = new byte[8][4][4];

		// for the first input of the compress1024 function we use predefined
		// V value(128-bit encoding of the intended hash output size (512 in this case))
		boolean flag = true;
		for (byte[][][] block : blocks) {

			if (flag) {
				for (int i = 0; i < Constants.V.length; i++) {
					V[i] = Logic.copyTwoDimentionalArray(Constants.V[i]);
				}
				flag = false;
			}

			// function that creates the current chaining variable
			VNext = Logic.compress1024(V, block);
			for (int i = 0; i < VNext.length; i++) {
				V[i] = Logic.copyTwoDimentionalArray(VNext[i]);
			}
		}

		// for the final output string we will use first 4 bytes of the V array
		// according the documentation.
		String output = Logic.forOutputStringFromV(V);

		return output;
	}

}
