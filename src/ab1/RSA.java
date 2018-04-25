package ab1;

import java.math.BigInteger;

/**
 * Interface für das RSA-Kryptosystem
 * 
 * @author Raphael Wigoutschnigg
 */
public interface RSA {

	/**
	 * Definiert die Bitlänge der Schlüssekomponenten
	 * 
	 * @param n
	 */
	public void init(int n);

	/**
	 * Liefert den öffentlichen Schlüssel
	 * 
	 * @return
	 */
	public PublicKey getPublicKey();

	/**
	 * Liefert den geheimen Schlüssel
	 * 
	 * @return
	 */
	public PrivateKey getPrivateKey();

	/**
	 * Verschlüsselt die Daten. Optional Aktivierung des Optimal Asymmetric
	 * Encryption Padding
	 * 
	 * @param data
	 * @param activateOAEP
	 * @return
	 */
	public byte[] encrypt(byte[] data, boolean activateOAEP);

	/**
	 * Entschlüsselt die Daten. Ob das OAEP verwendet wird, muss den Daten entnommen
	 * werden
	 * 
	 * @param datam
	 * @return
	 */
	public byte[] decrypt(byte[] data);

	/**
	 * Signiert die Daten
	 * 
	 * @param message
	 * @return
	 */
	public byte[] sign(byte[] message);

	/**
	 * Verifiziert die Signatur
	 * 
	 * @param message
	 * @param signature
	 * @return
	 */
	public Boolean verify(byte[] message, byte[] signature);

	public static class PublicKey {
		private BigInteger n;
		private BigInteger e;

		public PublicKey(BigInteger n, BigInteger e) {
			this.n = n;
			this.e = e;
		}

		public BigInteger getE() {
			return e;
		}

		public void setE(BigInteger e) {
			this.e = e;
		}

		public BigInteger getN() {
			return n;
		}

		public void setN(BigInteger n) {
			this.n = n;
		}
	}

	public static class PrivateKey {
		private BigInteger n;
		private BigInteger d;

		public PrivateKey(BigInteger n, BigInteger d) {
			this.n = n;
			this.d = d;
		}

		public BigInteger getD() {
			return d;
		}

		public void setD(BigInteger d) {
			this.d = d;
		}

		public BigInteger getN() {
			return n;
		}

		public void setN(BigInteger n) {
			this.n = n;
		}

	}
}