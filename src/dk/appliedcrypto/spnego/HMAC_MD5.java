/*
 * $Id: HMAC_MD5.java,v 1.1 2008-06-22 11:27:28 bofriis Exp $
 */
package dk.appliedcrypto.spnego;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * <p>
 * <small>SPNEGO SSO<br>
 * Copyright(c), Applied Crypto Aps, All rights reserved </small>
 * </p>
 * @author Jens Bo Friis, bofriis@gmail.com
 */
public class HMAC_MD5 {

	public HMAC_MD5() {
	}
	
	private static boolean isEqual(byte[] ba1, byte[] ba2) {
		if (ba1.length!=ba2.length)
			return false;
		for (int i=0; i<ba1.length; i++) {
			if (ba1[i]!=ba2[i])
				return false;
		}
		return true;
	}
	
	public static boolean verify(byte signeddata[], byte data[], byte secret[], byte salt[]) throws NoSuchAlgorithmException {
		return isEqual(digest(data, secret, salt), signeddata);
	}
	public static byte[] digest(byte data[], byte secret[], byte salt[]) throws NoSuchAlgorithmException {
		MessageDigest messagedigest = MessageDigest.getInstance("MD5");
		byte abyte3[] = new byte[65];
		byte abyte4[] = new byte[65];
		if (secret.length > 64) {
			messagedigest.reset();
			messagedigest.update(secret);
			secret = messagedigest.digest();
		}
		System.arraycopy(secret, 0, abyte3, 0, secret.length);
		System.arraycopy(secret, 0, abyte4, 0, secret.length);
		for (int i = 0; i < 64; i++) {
			abyte3[i] ^= 54;
			abyte4[i] ^= 92;
		}
		messagedigest.reset();
		messagedigest.update(abyte3);
		messagedigest.update(salt);
		messagedigest.update(data);
		byte abyte5[] = messagedigest.digest();
		messagedigest.reset();
		messagedigest.update(abyte4);
		messagedigest.update(abyte5);
		return messagedigest.digest();
	}
    
// 	public static void main(String[] args) throws Exception{
//		byte[] secret = "This is a secret password".getBytes();
//		byte[] data = "This is some data that has been signed".getBytes();
//		byte[] salt = "salt".getBytes();
//	
//		byte[] signeddata = digest(data, secret, salt);
//		System.out.println(HexDump.xdump(signeddata));
//		System.out.println(verify(signeddata, "This is some data that has been signed".getBytes(), secret, salt));	
//	}

}
