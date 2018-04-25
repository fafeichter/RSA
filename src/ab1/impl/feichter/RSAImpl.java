package ab1.impl.feichter;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import ab1.RSA;

public class RSAImpl implements RSA {

	private static final BigInteger ONE = BigInteger.ONE;
	private static final int BYTE_SIZE = Byte.SIZE;

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
		// TODO Auto-generated method stub
		return null;
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
}