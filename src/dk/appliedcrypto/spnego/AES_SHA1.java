package dk.appliedcrypto.spnego;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * <pre>
 * +-----------+----------+---------+-----+ 
 * |confounder | checksum | msg-seq | pad | 
 * +-----------+----------+---------+-----+
 * </pre>
 * 
 * <p>
 * <small>SPNEGO SSO<br>
 * Copyright(c), Applied Crypto Aps, All rights reserved </small>
 * </p>
 * @author Jens Bo Friis, bofriis@gmail.com
 * @see http://tools.ietf.org/html/rfc3961
 * @see http://tools.ietf.org/html/rfc3962
 */
public class AES_SHA1 extends EType{

	private final static boolean jce = false;
	
	private static final int BLOCK_SIZE = 16;

	private static final int DEFAULT_ITERATION_COUNT = 4096;

	private static final byte ZERO_IV[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

	static final byte KERBEROS_CONSTANT[] = { 107, 101, 114, 98, 101, 114, 111, 115 };

	private static final int hashSize = 12;

	private int keyLength;

	public AES_SHA1(int i) {
		keyLength = 0;
		keyLength = i;
	}

	private Cipher getCipher(byte key[], byte iv[], int mode) throws GeneralSecurityException {
		if (iv == null) {
			iv = new byte[key.length];
			for (int i = 0; i < iv.length; i++)
				iv[i] = 0;
		}

		SecretKeySpec secretkeyspec = new SecretKeySpec(key, "AES");
		Cipher cipher = Cipher.getInstance("AES/CTS/NoPadding");
		IvParameterSpec ivparameterspec = new IvParameterSpec(iv, 0, iv.length);
		cipher.init(mode, secretkeyspec, ivparameterspec);
		return cipher;
	}

	private int getChecksumLength() {
		return 12;
	}

	private static byte[] randomToKey(byte random[]) {
		return random;
	}

	private byte[] getHmac(byte key[], byte plaintext[]) throws GeneralSecurityException {

		SecretKeySpec secretkeyspec = new SecretKeySpec(key, "HMAC");
		Mac mac = Mac.getInstance("HmacSHA1");
		mac.init(secretkeyspec);
		byte abyte2[] = mac.doFinal(plaintext);
		byte abyte3[] = new byte[12];
		System.arraycopy(abyte2, 0, abyte3, 0, 12);
		return abyte3;
	}

	private byte[] dk(byte key[], byte abyte1[]) throws GeneralSecurityException {
		return randomToKey(dr(key, abyte1));
	}

	private byte[] dr(byte key[], byte abyte1[]) throws GeneralSecurityException {
		byte[] iv = new byte[16];
		Cipher cipher = getCipher(key, iv, Cipher.ENCRYPT_MODE);
		int i = cipher.getBlockSize();
		if (abyte1.length != i)
			abyte1 = nfold(abyte1, i * 8);
		byte abyte2[] = abyte1;
		int j = getKeySeedLength() >> 3;
		byte abyte3[] = new byte[j];
		boolean flag = false;
		for (int k = 0; k < j;) {
			byte abyte4[] = cipher.doFinal(abyte2);
			int l = j - k > abyte4.length ? abyte4.length : j - k;
			System.arraycopy(abyte4, 0, abyte3, k, l);
			k += l;
			abyte2 = abyte4;
		}

		return abyte3;
	}

	private static byte[] nfold(byte abyte0[], int i) {
		int j = abyte0.length;
		i >>= 3;
		int k = i;
		for (int l = j; l != 0;) {
			int i1 = l;
			l = k % l;
			k = i1;
		}

		int j1 = (i * j) / k;
		byte abyte1[] = new byte[i];
		Arrays.fill(abyte1, (byte) 0);
		int k1 = 0;
		for (int i2 = j1 - 1; i2 >= 0; i2--) {
			int l1 = (((j << 3) - 1) + ((j << 3) + 13) * (i2 / j) + (j - i2 % j << 3)) % (j << 3);
			int k2 = ((abyte0[(j - 1 - (l1 >>> 3)) % j] & 255) << 8 | abyte0[(j - (l1 >>> 3)) % j] & 255) >>> (l1 & 7) + 1 & 255;
			k1 += k2;
			int l2 = abyte1[i2 % i] & 255;
			k1 += l2;
			abyte1[i2 % i] = (byte) (k1 & 255);
			k1 >>>= 8;
		}

		if (k1 != 0) {
			for (int j2 = i - 1; j2 >= 0; j2--) {
				k1 += abyte1[j2] & 255;
				abyte1[j2] = (byte) (k1 & 255);
				k1 >>>= 8;
			}

		}
		return abyte1;
	}

	
	
	/**
	 * Password-Based Key Derivation Function
	 * 
	 * @param ac
	 * @param abyte0
	 * @param i
	 * @param j
	 * @return
	 * @throws GeneralSecurityException
	 */
	private static byte[] PBKDF2(char[] password, byte salt[], int iterationcount, int keylen) {
		// PBEKeySpec pbekeyspec = new PBEKeySpec(password, salt,
		// iterationcount, keylen);
		// SecretKeyFactory secretkeyfactory =
		// SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		// SecretKey secretkey = secretkeyfactory.generateSecret(pbekeyspec);
		// byte key[] = secretkey.getEncoded();

		if (!jce) {
			PBKDF2Parameters param = new PBKDF2Parameters("HmacSHA1", "UTF-8", salt, iterationcount);
			PBKDF2Engine pbkdf2 = new PBKDF2Engine(param);
			byte[] key = pbkdf2.deriveKey(new String(password), keylen);
			return key;
		} else {
			PBKDF2JCE pbkdf2 = new PBKDF2JCE();
			byte[] key = pbkdf2.deriveKeyHmacSHA1(salt, iterationcount, new String(password).getBytes(), keylen);

			return key;
		}
	}

	private static final int readBigEndian(byte abyte0[], int i, int j) {
		int k = 0;
		int l = (j - 1) * 8;
		for (; j > 0; j--) {
			k += (abyte0[i] & 255) << l;
			l -= 8;
			i++;
		}

		return k;
	}

	public byte[] encrypt(Key key, int messageType, byte[] cipher) throws GeneralSecurityException {
		throw new GeneralSecurityException("not implemented");
	}
	
	public byte[] decrypt(Key key, int messageType, byte[] cipher) throws GeneralSecurityException {
		byte[] iv = new byte[16];
		byte[] keydata = key.getEncoded();
		int confounderlen = 8;
		int j = 0;
		int k = cipher.length;
		return decrypt(keydata, messageType, iv, cipher, j, k);
	}

	private int getKeySeedLength() {
		return keyLength;
	}

	private byte[] decrypt(byte abyte0[], int i, byte iv[], byte ciphertext[], int j, int k) throws GeneralSecurityException {
		byte abyte3[] = decryptCTS(abyte0, i, iv, ciphertext, j, k, true);
		return abyte3;
	}

	private byte[] decryptRaw(byte abyte0[], int i, byte iv[], byte ciphertext[], int j, int k) throws GeneralSecurityException {
		byte abyte3[] = decryptCTS(abyte0, i, iv, ciphertext, j, k, false);
		return abyte3;
	}

	/**
	 * counfounder(16 or 8) | data | checksum(12)
	 * 
	 * @param abyte0
	 * @param i
	 *            messageType?
	 * @param iv
	 *            null?
	 * @param ciphertext
	 * @param j
	 *            start of data
	 * @param k
	 *            length of edata - len of checksum (12 bytes) - confounder (8
	 *            bytes), j+k = ciphertext.len
	 * @param flag
	 * @return
	 * @throws GeneralSecurityException
	 */
	private byte[] decryptCTS(byte abyte0[], int i, byte iv[], byte ciphertext[], int j, int k, boolean flag) throws GeneralSecurityException {
		if (iv == null) {
			iv = new byte[abyte0.length];
			for (int x = 0; x < iv.length; x++)
				iv[x] = 0;
		}

		int messageType = i;

		byte[] checksum = new byte[getChecksumLength()];
		byte[] confounder = new byte[8];
		byte[] data = new byte[ciphertext.length - checksum.length];

		System.arraycopy(ciphertext, 0, checksum, 0, checksum.length);
		System.arraycopy(ciphertext, checksum.length, confounder, 0, confounder.length);

		// System.arraycopy(edata, 0, confounder, 0, confounder.length);
		// System.arraycopy(edata, confounder.length, checksum, 0,
		// checksum.length);

		System.arraycopy(ciphertext, checksum.length, data, 0, data.length);

		byte key[];
		byte abyte4[];
		key = null;
		abyte4 = null;
		byte abyte6[];
		byte abyte10[];
		byte abyte5[] = new byte[5];
		abyte5[0] = (byte) (i >> 24 & 255);
		abyte5[1] = (byte) (i >> 16 & 255);
		abyte5[2] = (byte) (i >> 8 & 255);
		abyte5[3] = (byte) (i & 255);
		abyte5[4] = -86;

		key = dk(abyte0, abyte5);
		Cipher cipher = Cipher.getInstance("AES/CTS/NoPadding");

		SecretKeySpec secretkeyspec = new SecretKeySpec(key, "AES");
		IvParameterSpec ivparameterspec = new IvParameterSpec(iv, 0, iv.length);
		cipher.init(Cipher.DECRYPT_MODE, secretkeyspec, ivparameterspec);
		abyte6 = cipher.doFinal(ciphertext, j, k - getChecksumLength());
		byte abyte8[] = new byte[abyte6.length - 16];
		System.arraycopy(abyte6, 16, abyte8, 0, abyte8.length);
		return abyte8;
		// skip check test, the decoding will fail if it had been manipulated
		// with.
	}

	public byte[] stringToKey(char password[], byte salt[], byte abyte1[], int iterationcount) throws GeneralSecurityException {
		if (iterationcount == -1)
			iterationcount = DEFAULT_ITERATION_COUNT;
		if (abyte1 != null) {
			if (abyte1.length != 4)
				throw new RuntimeException("Invalid parameter");
			iterationcount = readBigEndian(abyte1, 0, 4);
//			System.out.println("REMOVE ME:"+iterationcount);
		}
		byte abyte2[] = randomToKey(PBKDF2(password, salt, iterationcount, getKeySeedLength()));
		byte abyte3[] = dk(abyte2, KERBEROS_CONSTANT);
		return abyte3;
	}

	public byte[] encrypt(EncryptionKey key, int messageType, byte[] cipher) throws KrbException {
		throw new KrbException(KrbException.KRB_GENERAL_ERROR, "not implemented");
	}
	
	public byte[] decrypt(EncryptionKey key, int messageType, byte[] cipher) throws KrbException {
		byte[] iv = new byte[16];
		byte[] keydata = key.getKeyValue();
		int confounderlen = 8;
		int j = 0;
		int k = cipher.length;
		try {
			return decrypt(keydata, messageType, iv, cipher, j, k);
		} catch (GeneralSecurityException e) {
			throw new KrbException(KrbException.KRB_GENERAL_ERROR, e);
		}
	}

}
