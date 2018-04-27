package ab1.impl.feichter;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import ab1.RSA;

/**
 * Implementation of the RSA Cryptosystem
 * 
 * @author Fabian Feichter
 *
 */
public class RSAImpl implements RSA {

	/**
	 * Helper constants
	 */
	private static final BigInteger ZERO = BigInteger.ZERO;
	private static final BigInteger ONE = BigInteger.ONE;
	private static final int BYTE_SIZE = Byte.SIZE;

	/**
	 * Byte to define wether it is encrytped with oaep or not
	 */
	private static final byte OAEP_ON = 1;
	private static final byte OAEP_OFF = 0;

	/**
	 * Padding is used because of the possible different length of decrypted blocks
	 */
	private static final byte[] PADDING = { 0, 0, 0, 0, 0, 0, 1 };
	private static final int PADDING_SIZE = PADDING.length;

	/**
	 * Used algorithm to calculate hash codes
	 */
	private static final String HASH_ALGORITHM = "SHA-256";

	/**
	 * Keys
	 */
	private PublicKey publicKey = null;
	private PrivateKey privateKey = null;

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
		byte oaepMode = OAEP_OFF;

		if (!isEmpty(data)) {
			if (!activateOAEP) {
				cipher = rsaEncrypt(data, this.publicKey.getE());
			} else {
				oaepMode = OAEP_ON;
				// TODO
			}
		}

		if (cipher != null) {
			byte[] temp = Arrays.copyOf(cipher, cipher.length);
			cipher = new byte[temp.length + 1];
			cipher[0] = oaepMode;
			System.arraycopy(temp, 0, cipher, 1, temp.length);
		}

		return cipher;
	}

	@Override
	public byte[] decrypt(byte[] data) {
		byte[] original = null;
		byte oaepMode = data[0];

		// remove first byte again
		byte[] cipher = new byte[data.length - 1];
		cipher = Arrays.copyOfRange(data, 1, data.length);

		if (oaepMode == OAEP_ON) {
			// TODO
		} else {
			original = rsaDecrypt(cipher, this.privateKey.getD());
		}

		return original;
	}

	@Override
	public byte[] sign(byte[] message) {
		byte[] signature = null;

		if (!isEmpty(message)) {
			byte[] cipher = rsaEncrypt(toHash(message), this.privateKey.getD());
			signature = Arrays.copyOfRange(cipher, 1, cipher.length);
		}

		return signature;
	}

	@Override
	public Boolean verify(byte[] message, byte[] signature) {
		Boolean verified = null;

		if (!isEmpty(message) && !isEmpty(signature)) {
			byte[] signatureExtended = new byte[signature.length + 1];
			signatureExtended[0] = 0;

			for (int i = 0; i < signature.length; i++) {
				byte b = signature[i];
				signatureExtended[i + 1] = b;
			}

			byte[] messageHash = toHash(message);
			byte[] decryptedMessageHash = rsaDecrypt(signatureExtended, this.publicKey.getE());
			verified = Arrays.equals(messageHash, decryptedMessageHash);
		}

		return verified;
	}

	/**
	 * Encrypts a message with the specified key. If the encryption is not
	 * applicable to the specified parameters the result is null.
	 * 
	 * @param data
	 *            Data to encrypt as array of bytes
	 * @param key
	 *            Key as BigInteger
	 * @return Cipher as array of bytes
	 */
	private byte[] rsaEncrypt(byte[] data, BigInteger key) {
		byte[] cipher = null;

		if (!isEmpty(data) && key != null) {
			int originalLength = (int) Math.ceil(this.publicKey.getN().bitLength() / 2 / (double) BYTE_SIZE);
			int blockLength = originalLength - PADDING_SIZE;
			int cipherBlockLength = this.publicKey.getN().toByteArray().length;
			int cipherLength = (int) Math.ceil(data.length / (double) blockLength) * cipherBlockLength;

			cipher = new byte[cipherLength];

			int steps = 1;
			do {
				int start = (steps - 1);
				byte[] messagePart = new byte[originalLength];
				int copyLength = data.length - start * blockLength < blockLength ? data.length - start * blockLength
						: blockLength;

				System.arraycopy(PADDING, 0, messagePart, 0, PADDING_SIZE);
				System.arraycopy(data, start * blockLength, messagePart, PADDING_SIZE, copyLength);

				messagePart = Arrays.copyOfRange(messagePart, 0, copyLength + PADDING_SIZE);
				byte[] cipherBlock = proccessByteBlock(messagePart, key, this.publicKey.getN());
				System.arraycopy(cipherBlock, 0, cipher,
						start * cipherBlockLength + (cipherBlockLength - cipherBlock.length), cipherBlock.length);

				steps++;
			} while ((steps - 1) * blockLength < data.length);
		}

		return cipher;
	}

	/**
	 * Decrypts a cipher with the specified key. If the decryption is not applicable
	 * to the specified parameters the result is null.
	 * 
	 * @param data
	 *            Cipher to decrypt as array of bytes
	 * @param key
	 *            Key as BigInteger
	 * @return Original message as array of bytes
	 */
	private byte[] rsaDecrypt(byte[] data, BigInteger key) {
		byte[] original = null;

		if (!isEmpty(data) && key != null) {
			int originalLength = (int) Math.ceil(this.publicKey.getN().bitLength() / 2 / (double) BYTE_SIZE);
			int blockLength = originalLength - PADDING_SIZE;
			int dataBlockLength = this.publicKey.getN().toByteArray().length;
			int messageLength = (int) Math.ceil(data.length / (double) dataBlockLength) * blockLength;

			original = new byte[messageLength];

			int steps = 1;
			int pos = 0;
			do {
				int start = steps - 1;
				byte[] dataPart = Arrays.copyOfRange(data, start * dataBlockLength,
						start * dataBlockLength + dataBlockLength);
				byte[] messageBlock = proccessByteBlock(dataPart, key, this.privateKey.getN());

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
		}

		return original;
	}

	/**
	 * Returns data^exponent MOD modulus ("Square & Multiply"). If the calculation
	 * is not applicable to the specified parameters the result is null.
	 * 
	 * @param data
	 *            Data as array of bytes
	 * @param exponent
	 *            Exponent as BigInteger
	 * @param modulus
	 *            Modulus as BigInteger
	 * @return data^exponent MOD modulus as array of bytes
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
	 * @param arr
	 *            Array
	 * 
	 * @return true if the specified array is empty, otherwise false
	 */
	private boolean isEmpty(byte[] arr) {
		return arr == null || arr.length == 0;
	}

	/**
	 * Returns a hash code value for the specified data array.
	 * 
	 * @param data
	 *            array of bytes to calculate the hash for
	 * @return hash code value for the specified data as array of bytes
	 */
	private byte[] toHash(byte[] data) {
		byte[] hash = null;

		try {
			MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);
			hash = digest.digest(data);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		return hash;
	}
}