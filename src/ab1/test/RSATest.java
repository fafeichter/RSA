package ab1.test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.util.Arrays;
import java.util.Random;

import org.junit.Before;
import org.junit.Test;

import ab1.RSA;
import ab1.RSA.PrivateKey;
import ab1.RSA.PublicKey;
import ab1.impl.FeichterUrbaniProhinig.RSAImpl;

public class RSATest {
	RSA rsa = new RSAImpl();

	private static int KEYLENGTH = 1024;
	private static int TESTCOUNT_LONG = 100;
	private static int TESTCOUNT_SHORT = 1000;

	private static int TESTCOUNT_SIGN = 1000;

	@Before
	public void initialize() {
		rsa.init(KEYLENGTH);
	}

	// 1 Pts
	@Test
	public void testInit() {

		PublicKey pub = rsa.getPublicKey();
		PrivateKey priv = rsa.getPrivateKey();

		assertEquals(KEYLENGTH, pub.getN().bitLength());
		assertEquals(KEYLENGTH, priv.getN().bitLength());
	}

	// 1 Pts
	@Test
	public void testEncryptionShort() {

		Random r = new Random(System.currentTimeMillis());
		int dataLength = 4;
		byte[] data = new byte[dataLength];

		for (int i = 0; i < TESTCOUNT_SHORT; i++) {
			r.nextBytes(data);

			testRSANoOAEP(data, r);
		}
	}

	// 2 Pts
	@Test
	public void testEncryptionLong() {

		Random r = new Random(System.currentTimeMillis());

		for (int i = 0; i < TESTCOUNT_LONG; i++) {
			int dataLength = KEYLENGTH / 8 * (i + 1);
			byte[] data = new byte[dataLength];

			r.nextBytes(data);

			testRSANoOAEP(data, r);
		}
	}

	private void testRSANoOAEP(byte[] data, Random r) {
		byte[] cipher1 = rsa.encrypt(data, false);
		byte[] cipher2 = rsa.encrypt(data, false);

		assertArrayEquals(cipher1, cipher2);

		byte[] dataChanged = Arrays.copyOf(data, data.length);
		dataChanged[0] = (byte) (dataChanged[0] ^ (byte) 1);
		byte[] cipherDiff = rsa.encrypt(dataChanged, false);

		assertEquals(false, Arrays.equals(cipher1, cipherDiff));

		if (r.nextBoolean()) {
			// Keine �nderung des Schl�sseltexts
			byte[] cipher = rsa.encrypt(data, false);

			byte[] message_decrypted = rsa.decrypt(cipher);

			assertArrayEquals(data, message_decrypted);
		} else {
			byte[] cipher = rsa.encrypt(data, false);

			// Baue Fehler ab der H�lfte der Daten ein (davor stehen eventuell
			// Protokolldaten)
			for (int j = data.length / 2; j < data.length; j++)
				cipher[j] = (byte) (cipher[j] ^ 0xFF);

			byte[] message_decrypted = rsa.decrypt(cipher);

			assertEquals(false, Arrays.equals(data, message_decrypted));
		}
	}

	// 1 Pts
	@Test
	public void testEncryptionShort_OAEP() {

		Random r = new Random(System.currentTimeMillis());
		int dataLength = 4;
		byte[] data = new byte[dataLength];

		for (int i = 0; i < TESTCOUNT_SHORT; i++) {
			r.nextBytes(data);

			testRSAOAEP(data, r);
		}
	}

	// 2 Pts
	@Test
	public void testEncryptionLong_OAEP() {
		Random r = new Random(System.currentTimeMillis());

		for (int i = 0; i < TESTCOUNT_LONG; i++) {
			int dataLength = KEYLENGTH / 8 * (i + 1);
			byte[] data = new byte[dataLength];
			r.nextBytes(data);

			testRSAOAEP(data, r);
		}
	}

	private void testRSAOAEP(byte[] data, Random r) {
		// Chiffrate m�ssen unterschiedlich sein
		byte[] cipher1 = rsa.encrypt(data, true);
		byte[] cipher2 = rsa.encrypt(data, true);
		assertEquals(false, Arrays.equals(cipher1, cipher2));

		// Entschl�sselt muss es wieder das gleiche sein
		byte[] decipher1 = rsa.decrypt(cipher1);
		byte[] decipher2 = rsa.decrypt(cipher2);
		assertArrayEquals(decipher1, decipher2);

		if (r.nextBoolean()) {
			// Keine �nderung des Schl�sseltexts
			byte[] cipher = rsa.encrypt(data, false);

			byte[] message_decrypted = rsa.decrypt(cipher);

			assertArrayEquals(data, message_decrypted);
		} else {
			byte[] cipher = rsa.encrypt(data, false);

			// Baue Fehler ab der H�lfte der Daten ein (davor stehen eventuell
			// Protokolldaten)
			for (int j = data.length / 2; j < data.length; j++)
				cipher[j] = (byte) (cipher[j] ^ 0xFF);

			byte[] message_decrypted = rsa.decrypt(cipher);

			assertEquals(false, Arrays.equals(data, message_decrypted));
		}
	}

	// 3 Pts
	@Test
	public void testSignature() {

		Random r = new Random(System.currentTimeMillis());

		for (int i = 0; i < TESTCOUNT_SIGN; i++) {
			int dataLength = KEYLENGTH / 8 * i + 1;
			byte[] data = new byte[dataLength];

			r.nextBytes(data);

			if (r.nextBoolean()) {
				// Keine �nderung der Signatur/Daten
				byte[] sign = rsa.sign(data);

				assertEquals(true, sign.length <= KEYLENGTH / 8); // Signatur darf maximal so lang wie der Schl�ssel
																	// sein (einfache Abfrage, ob wohl gehasht wurde)

				assertEquals(true, rsa.verify(data, sign));
			} else {
				byte[] sign = rsa.sign(data);

				// Baue einen einzigen Bit-Fehler in die Daten ein
				int pos = r.nextInt(data.length);
				data[pos] = (byte) (data[pos] ^ 0x01);

				assertEquals(true, sign.length <= KEYLENGTH / 8); // Signatur darf maximal so lang wie der Schl�ssel
																	// sein (einfache Abfrage, ob wohl gehasht wurde)

				assertEquals(false, rsa.verify(data, sign));
			}
		}
	}
}
