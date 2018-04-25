package ab1.impl.feichter;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import ab1.RSA;

public class RSAImpl implements RSA {

	private static final BigInteger ZERO = BigInteger.ZERO;
	private static final BigInteger ONE = BigInteger.ONE;
	private static final int BYTE_SIZE = Byte.SIZE;
	private static final byte[] PADDING = { 0, 0, 0, 0, 0, 0, 1 };
	private static final int PADDING_SIZE = PADDING.length;

	private PublicKey publicKey;
	private PrivateKey privateKey;

	@Override
	public void init(int n) {
		// n must be a multiple of 8
		if (n > 0 && n % BYTE_SIZE == 0) {
			// Find two prime numbers for p and q
			Random random = new SecureRandom();
			BigInteger p = BigInteger.probablePrime(n / 2, random);
			BigInteger q = null;
			do {
				q = BigInteger.probablePrime(n / 2, random);
			} while (p.equals(q) || p.multiply(q).bitLength() != n);

			// n = p * q
			BigInteger publicKey = p.multiply(q);

			// φ(n) = (p - 1) * (q - 1)
			BigInteger phi = p.subtract(ONE).multiply(q.subtract(ONE));

			// Find e such that ggT(e, φ(n)) = 1
			BigInteger e = BigInteger.probablePrime(n / 2, random);
			while (phi.gcd(e).compareTo(ONE) > 0 && e.compareTo(phi) < 0) {
				e = e.add(ONE);
			}

			// Find d such that d * e MOD φ(n) = 1
			BigInteger d = e.modInverse(phi);

			this.publicKey = new PublicKey(publicKey, e);
			this.privateKey = new PrivateKey(publicKey, d);
		}
	}

	@Override
	public PublicKey getPublicKey() {
		return this.publicKey;
	}

	@Override
	public PrivateKey getPrivateKey() {
		return this.privateKey;
	}

	@Override
	public byte[] encrypt(byte[] data, boolean activateOAEP) {
		byte[] cipher = null;

		if (!isEmpty(data)) {
			if (!activateOAEP) {
				int originalLength = (int) Math.ceil(getPublicKey().getN().bitLength() / 2 / (double) BYTE_SIZE);
				int blockLength = originalLength - PADDING_SIZE;
				int cipherBlockLength = getPublicKey().getN().toByteArray().length;
				int cipherLength = (int) Math.ceil(data.length / (double) blockLength) * cipherBlockLength;
				int steps = 1;

				cipher = new byte[cipherLength];
				
				do {
					int start = (steps - 1);
					byte[] messagePart = new byte[originalLength];
					int copyLength = data.length - start * blockLength < blockLength ? data.length - start * blockLength : blockLength;
					
					System.arraycopy(PADDING, 0, messagePart, 0, PADDING_SIZE);
					System.arraycopy(data, start * blockLength, messagePart, PADDING_SIZE, copyLength);
					
					messagePart = Arrays.copyOfRange(messagePart, 0, copyLength + PADDING_SIZE);
					byte[] cipherBlock = this.proccessByteBlock(messagePart, getPublicKey().getE(), getPublicKey().getN());
					System.arraycopy(cipherBlock, 0, cipher, start * cipherBlockLength + (cipherBlockLength - cipherBlock.length), cipherBlock.length);
					
					steps++;
				} while ((steps - 1) * blockLength < data.length);
			} else {
				// TODO
			}
		}

		return cipher;
	}

	@Override
	public byte[] decrypt(byte[] data) {
		// TODO Auto-generated method stub
				return null;
	}

	@Override
	public byte[] sign(byte[] message) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Boolean verify(byte[] message, byte[] signature) {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 * Returns data^exponent MOD modulus ("Square & Multiply"). If the calculation
	 * is not applicable to the specified parameters the result is null.
	 * 
	 * @param data		Data
	 * @param exponent	Exponent
	 * @param modulus	Modulus
	 * @return 			data^exponent MOD modulus
	 */
	private byte[] proccessByteBlock(byte[] data, BigInteger exponent, BigInteger modulus) {
		byte[] result = null;
		if (!isEmpty(data) && modulus.compareTo(ZERO) == 1 && exponent.compareTo(ZERO) == 1) {
			result = new BigInteger(data).modPow(exponent, modulus).toByteArray();
		}
		return result;
	}

	/**
	 * Returns true if the specified array is empty, otherwise false.
	 * 
	 * @param arr	Array
	 * 
	 * @return 		true if the specified array is empty, otherwise false
	 */
	private boolean isEmpty(byte[] arr) {
		return arr == null || arr.length == 0;
	}
}