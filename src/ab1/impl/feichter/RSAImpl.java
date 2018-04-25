package ab1.impl.feichter;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
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
				cipher = rsaEncryption(data, false);
			} else {
				// TODO
			}
		}

		return cipher;
	}

	private byte[] rsaEncryption(byte[] data, boolean isSignature) {
		byte[] cipher;
		int originalLength = (int) Math.ceil(getPublicKey().getN().bitLength() / 2 / (double) BYTE_SIZE);
		int blockLength = originalLength - PADDING_SIZE;
		int cipherBlockLength = getPublicKey().getN().toByteArray().length;
		int cipherLength = (int) Math.ceil(data.length / (double) blockLength) * cipherBlockLength;
		
		cipher = new byte[cipherLength];
		
		int steps = 1;
		do {
			int start = (steps - 1);
			byte[] messagePart = new byte[originalLength];
			int copyLength = data.length - start * blockLength < blockLength ? data.length - start * blockLength : blockLength;
			
			System.arraycopy(PADDING, 0, messagePart, 0, PADDING_SIZE);
			System.arraycopy(data, start * blockLength, messagePart, PADDING_SIZE, copyLength);
			
			messagePart = Arrays.copyOfRange(messagePart, 0, copyLength + PADDING_SIZE);
			byte[] cipherBlock = this.proccessByteBlock(messagePart, isSignature ? getPrivateKey().getD() : getPublicKey().getE(), getPublicKey().getN());
			System.arraycopy(cipherBlock, 0, cipher, start * cipherBlockLength + (cipherBlockLength - cipherBlock.length), cipherBlock.length);
			
			steps++;
		} while ((steps - 1) * blockLength < data.length);
		return cipher;
	}

	@Override
	public byte[] decrypt(byte[] data) {
		byte[] original = null;

		if (false) {
			// TODO
		} else {
			original = rsaDecrypt(data, false);
		}

		return original;
	}
	
	private byte[] rsaDecrypt(byte[] data, boolean isSignature) {
		byte[] original = null;
		int originalLength = (int) Math.ceil(getPublicKey().getN().bitLength() / 2 / (double) BYTE_SIZE);
		int blockLength = originalLength - PADDING_SIZE;
		int dataBlockLength = getPublicKey().getN().toByteArray().length;
		int messageLength = (int) Math.ceil(data.length / (double) dataBlockLength) * blockLength;

		original = new byte[messageLength];

		int steps = 1;
		int pos = 0;
		do {
			int start = steps - 1;
			byte[] dataPart = Arrays.copyOfRange(data, start * dataBlockLength, start * dataBlockLength + dataBlockLength);
			byte[] messageBlock = this.proccessByteBlock(dataPart, isSignature ? getPublicKey().getE() : getPrivateKey().getD(), getPrivateKey().getN());

			if (messageBlock[0] != 1) {
				return new byte[0];
			}

			if (messageBlock.length < original.length) {
				System.arraycopy(messageBlock, 0 + 1, original, pos, messageBlock.length - 1);
			}

			pos += messageBlock.length - 1;
			steps++;
		} while (steps * dataBlockLength <= data.length);

		original = Arrays.copyOfRange(original, 0, pos);
		return original;
	}

	@Override
	public byte[] sign(byte[] message) {
		byte[] signature = rsaEncryption(toHash(message), true);
		return Arrays.copyOfRange(signature, 1, signature.length);
	}

	@Override
	public Boolean verify(byte[] message, byte[] signature) {
		byte[] signatureRichtig = new byte[signature.length+1];
		signatureRichtig[0] = 0;
		for (int i = 0; i < signature.length; i++) {
			byte b = signature[i];
			signatureRichtig[i+1] = b;
		}
		
		return Arrays.equals(rsaDecrypt(signatureRichtig, true), toHash(message));
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
	
	private byte[] toHash(byte[] data) {
		byte[] hash = null;
		
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			hash = digest.digest(data);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
		return hash;
	}
}