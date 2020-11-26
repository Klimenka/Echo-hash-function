package domain.proof.hashing.echo;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.List;

import domain.Asset;
import domain.Chain;
import domain.Reward;
import domain.proof.Proof;
import domain.proof.difficulty.DifficultyAssessorFactory;
import util.IllegalProofException;
import util.MathUtil;

public class EchoProof extends Proof {

	private static final long serialVersionUID = 12345453567L;

	private BigInteger original; // Excluding the nonce
	private long nonce;
	private BigInteger hash;
	private int difficulty;

	public EchoProof(BigInteger original, long nonce, BigInteger hash, Asset asset, Date moment) throws NoSuchAlgorithmException, IOException {
		super();
		this.original = original;
		this.nonce = nonce;
		this.hash = hash;
		this.difficulty = DifficultyAssessorFactory.getAssessor(this.getClass()).getDifficulty(moment);
		if (!isValid()) {
			throw new IllegalProofException("Hash incorrect or number of leading zero bits too low");
		}
		super.reward = calculateReward(asset);
	}
	public EchoProof(BigInteger original, long nonce, BigInteger hash, Asset asset) throws NoSuchAlgorithmException, IOException {
		this(original, nonce, hash, asset, new Date());
	}

	@Override
	public boolean equals(Proof o) {
		if (o instanceof EchoProof) {
			EchoProof other = (EchoProof) o;
			return this.hash.equals(other.hash);
		}
		else {
			return false;
		}
	}

	@Override
	public boolean isValid() throws NoSuchAlgorithmException, IOException {
		BigInteger toHash = original;
		Chain chain = Chain.instance(Asset.getDefault());
		List<Proof> existingProofs = chain.getProofs(EchoProof.class,  false);
		if (!existingProofs.contains(this)) {
			toHash = chain.getMerkleRoot();
		}
		int rounds = MathUtil.binlog(difficulty);
		for (int i=0; i<rounds; i++) {
			toHash = hash(toHash, nonce);
		}	
		if (!toHash.equals(hash)) {
			return false;
		}
		return MathUtil.checkTrailingZeroes(toHash, difficulty);
	}
	private BigInteger hash(BigInteger input, long nonce) {
		byte[] toHash = input.toByteArray();
		byte[] nonceBytes = MathUtil.longtoBytes(nonce);
		byte[] originalBytes = new byte[toHash.length + nonceBytes.length];
		System.arraycopy(toHash, 0, originalBytes, 0, toHash.length);
		System.arraycopy(nonceBytes, 0, originalBytes, toHash.length, nonceBytes.length);
		BigInteger hashed = new BigInteger(Echo.hash(originalBytes), 16);
		return hashed;
	}

	@Override
	public Reward calculateReward(Asset asset) throws NoSuchAlgorithmException, IOException {
		return new Reward(Asset.getDefault(), BigInteger.ONE);
	}

	@Override
	public Object[] getProofValues() {
		Object[] result = new Object[4];
		result[0] = original;
		result[1] = nonce;
		result[2] = hash;
		result[3] = difficulty;
		return result;
	}

	@Override
	public String getProofValuesTags() {
		// TODO Auto-generated method stub
		StringBuilder result = new StringBuilder("\t\toriginal=\"");
		result.append(original.toString(16));
		result.append(("\"\n\t\tnonce=\""));
		result.append(nonce);
		result.append(("\"\n\t\t\thash=\""));
		result.append(hash.toString(16));
		result.append(("\"\n\t\tdifficulty=\""));
		result.append(difficulty);
		result.append(("\"\n\t\ttrailingZeroes=\""));
		result.append(MathUtil.numberOfTrailingZeroes(hash));
		result.append("\">\n");
		return new String(result);
	}

}
