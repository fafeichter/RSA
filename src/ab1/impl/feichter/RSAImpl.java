package ab1.impl.feichter;

import java.io.UnsupportedEncodingException;
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

	private static final String PADDING_STRING = "SYSSEC";
	private static final String UTF_8 = "UTF-8";

	public static final SecureRandom random = new SecureRandom();

	/**
	 * Keys
	 */
	private PublicKey publicKey = null;
	private PrivateKey privateKey = null;

	/**
	 * Returns a hash code value for the specified data array.
	 * 
	 * @param data
	 *            array of bytes to calculate the hash for
	 * @return hash code value for the specified data as array of bytes
	 */
	private static final byte[] toHash(byte[] data) {
		byte[] hash = null;

		try {
			MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);
			hash = digest.digest(data);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		return hash;
	}
	
	/**
	 * Implementation of the masking function MGF1.
	 * 
	 * @param seed
	 * @param seedOffser
	 * @param seedLength
	 * @param desiredLength - the desired length of the mask
	 * 
	 * @return hash code value for the specified data as array of bytes
	 */
	public static final byte[] MGF1(byte[] seed, int seedOffset, int seedLength, int desiredLength)
			throws NoSuchAlgorithmException {
		int hLen = 32;
		int offset = 0;
		int i = 0;
		byte[] mask = new byte[desiredLength];
		byte[] temp = new byte[seedLength + 4];
		System.arraycopy(seed, seedOffset, temp, 4, seedLength);
		while (offset < desiredLength) {
			temp[0] = (byte) (i >>> 24);
			temp[1] = (byte) (i >>> 16);
			temp[2] = (byte) (i >>> 8);
			temp[3] = (byte) i;
			int remaining = desiredLength - offset;
			System.arraycopy(toHash(temp), 0, mask, offset, remaining < hLen ? remaining : hLen);
			offset = offset + hLen;
			i = i + 1;
		}
		return mask;
	}

	@Override
	public void init(int n) {
		// n must be a multiple of 8
		if (n > 0 && n % BYTE_SIZE == 0) {
			// Find two prime numbers for p and q
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
		byte oaepMode = activateOAEP ? OAEP_ON : OAEP_OFF;

		if (!isEmpty(data)) {
			cipher = rsaEncrypt(data, this.publicKey.getE(), activateOAEP);
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
		boolean activateOAEP = oaepMode == OAEP_ON;

		// remove first byte again
		byte[] cipher = new byte[data.length - 1];
		cipher = Arrays.copyOfRange(data, 1, data.length);

		original = rsaDecrypt(cipher, this.privateKey.getD(), activateOAEP);

		return original;
	}

	@Override
	public byte[] sign(byte[] message) {
		byte[] signature = null;

		if (!isEmpty(message)) {
			byte[] cipher = rsaEncrypt(toHash(message), this.privateKey.getD(), false);
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
			byte[] decryptedMessageHash = rsaDecrypt(signatureExtended, this.publicKey.getE(), false);
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
	private byte[] rsaEncrypt(byte[] data, BigInteger key, boolean oaepOn) {
		byte[] cipher = null;

		if (!isEmpty(data) && key != null) {
			if (oaepOn) {
				int rounds = Math.max(1, (int) Math.ceil(data.length/128));
				int newDataLen = rounds * 256;
				byte[] newData = new byte[newDataLen];
				
				for(int i  = 0; i < rounds; i++) {
					byte[] toPad = Arrays.copyOfRange(data, i*128, Math.min((i+1)*128, data.length));
					byte[] padded = oaepPad(toPad);
					
					System.arraycopy(padded, 0, newData, i*256, padded.length);
				}
				
				data = newData;
			}
			
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
	private byte[] rsaDecrypt(byte[] data, BigInteger key, boolean oaepOn) {
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
			
			if (oaepOn) {
				int rounds = original.length/256;

				byte[] originalTemp = new byte[rounds*128];

				for(int i  = 0; i < rounds; i++) {
					byte[] toUnpad = Arrays.copyOfRange(originalTemp, i*256, ((i+1)*256));

					byte[] unpadded = oaepUnpad(toUnpad);
					
					if(null == unpadded) {
						return new byte[0];
					}
					
					System.arraycopy(unpadded, 0, originalTemp, i*128, unpadded.length);
					
					if(i == rounds) {
						originalTemp = Arrays.copyOfRange(originalTemp, 0, (rounds-1) * 128 + unpadded.length);
					}
				}
				
				original = originalTemp;
			}
			
			
		}

		return original;
	}
	
	/**
	 * Pads a message using oaep
	 * 
	 * @param data
	 *            Data to encrypt as array of bytes
	 * 
	 * @return oaep padded byte array to decrypt using rsa
	 */
	private byte[] oaepPad(byte[] data) {
		byte[] padded = null;
		
		try {
			int length = 256;
			int mLen = data.length;
			int hLen = 32;
			if (mLen > length - (hLen << 1) - 1) {
				return null;
			}
			int zeroPad = length - mLen - (hLen << 1) - 1;
			byte[] dataBlock = new byte[length - hLen];

			byte[] rand = new byte[hLen];
			random.nextBytes(rand);

			System.arraycopy(toHash(PADDING_STRING.getBytes(UTF_8)), 0, dataBlock, 0, hLen);

			System.arraycopy(data, 0, dataBlock, hLen + zeroPad + 1, mLen);
			dataBlock[hLen + zeroPad] = 1;
			byte[] seed = new byte[hLen];
			random.nextBytes(seed);
			byte[] dataBlockMask = MGF1(seed, 0, hLen, length - hLen);
			for (int i = 0; i < length - hLen; i++) {
				dataBlock[i] ^= dataBlockMask[i];
			}
			byte[] seedMask = MGF1(dataBlock, 0, length - hLen, hLen);
			for (int i = 0; i < hLen; i++) {
				seed[i] ^= seedMask[i];
			}
			padded = new byte[length];
			System.arraycopy(seed, 0, padded, 0, hLen);
			System.arraycopy(dataBlock, 0, padded, hLen, length - hLen);
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return padded;

	}

	/**
	 * Unpads a message using oaep
	 * 
	 * @param data
	 *            the padded data
	 * 
	 * @return original message before padding
	 */
	private byte[] oaepUnpad(byte[] paddedData) {
		byte[] unpadded = null;
		try {
		        int mLen = paddedData.length;
		        int hLen = 32;
		        if (mLen < (hLen << 1) + 1) {
		            return null;
		        }
		        byte[] copy = new byte[mLen];
		        System.arraycopy(paddedData, 0, copy, 0, mLen);
		        byte[] seedMask = MGF1(copy, hLen, mLen - hLen, hLen);
		        for (int i = 0; i < hLen; i++) {
		            copy[i] ^= seedMask[i];
		        }
		        byte[] paramsHash = toHash(PADDING_STRING.getBytes("UTF-8"));
		        byte[] dataBlockMask = MGF1(copy, 0, hLen, mLen - hLen);
		        int index = -1;
		        for (int i = hLen; i < mLen; i++) {
		            copy[i] ^= dataBlockMask[i - hLen];
		            if (i < (hLen << 1)) {
		                if (copy[i] != paramsHash[i - hLen]) {
		                    return null;
		                }
		            } else if (index == -1) {
		                if (copy[i] == 1) {
		                    index = i + 1;
		                }
		            }
		        }
		        if (index == -1 || index == mLen) {
		            return null;
		        }
		        unpadded = new byte[mLen - index];
		        System.arraycopy(copy, index, unpadded, 0, mLen - index);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
				
		return unpadded;
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

}