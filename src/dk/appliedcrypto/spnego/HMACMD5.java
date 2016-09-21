package dk.appliedcrypto.spnego;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

/**
 * HMAC_MD5 implementation
 * 
 * Picked up somewhere on the internet, original author is lost.
 * 
 * <p>
 * <small>SPNEGO SSO<br>
 * Copyright(c), Applied Crypto Aps, All rights reserved </small>
 * </p>
 * @author Jens Bo Friis, bofriis@gmail.com
 */
public class HMACMD5 {
	/**
	 * Calculates the HMAC-MD5 hash of the given data using the specified
	 * hashing key.
	 * 
	 * @param data
	 *            The data for which the hash will be calculated.
	 * @param key
	 *            The hashing key.
	 * 
	 * @return The HMAC-MD5 hash of the given data.
	 */
	public static byte[] hmacMD5(byte[] data, byte[] key) throws KrbException {
		byte[] ipad = new byte[64];
		byte[] opad = new byte[64];
		for (int i = 0; i < 64; i++) {
			ipad[i] = (byte) 0x36;
			opad[i] = (byte) 0x5c;
		}
		for (int i = key.length - 1; i >= 0; i--) {
			ipad[i] ^= key[i];
			opad[i] ^= key[i];
		}
		byte[] content = new byte[data.length + 64];
		System.arraycopy(ipad, 0, content, 0, 64);
		System.arraycopy(data, 0, content, 64, data.length);
		MessageDigest md5 = null;
		try {
			md5 = MessageDigest.getInstance("MD5");
			data = md5.digest(content);

		} catch (GeneralSecurityException e) {
			KrbException ke = new KrbException(KrbException.KRB_GENERAL_ERROR,"JCE provider may not be installed. " + e.getMessage());
			ke.initCause(e);
			throw ke;
		}

		content = new byte[data.length + 64];
		System.arraycopy(opad, 0, content, 0, 64);
		System.arraycopy(data, 0, content, 64, data.length);
		return md5.digest(content);
	}

	public static String hex_md5(String s) throws Exception {
		MessageDigest md5 = MessageDigest.getInstance("MD5");
		return new BigInteger(md5.digest(s.getBytes())).toString(16);
	}

//	public static void main(String[] args) throws Exception {
//		System.out.println("MD5(test)="+hex_md5("test"));
//		byte[] key = new byte[16];
//		for (int i = 0; i < key.length; i++)
//			key[i] = (byte) 0xaa;
//		System.out.println(HexDump.xdump(key));
//		System.out.println(new String(Hex.encode(key)));
//		byte[] data = new byte[50];
//		for (int i = 0; i < data.length; i++)
//			data[i] = (byte) 0xdd;
//		System.out.println(new String(Hex.encode(data)));
//		System.out.println(HexDump.xdump(data));
//		System.out.println("0000: 56 BE 34 52 1D 14 4C 88 - DB B8 C7 33 F0 E8 B3 F6  V.4R..L....3....");
//		byte[] digest = hmacMD5(data, key);
//		System.out.println(HexDump.xdump(digest));
//	}
}
