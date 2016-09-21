package dk.appliedcrypto.spnego;

import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * 
 * <p>
 * <small>SPNEGO SSO<br>
 * Copyright(c), Applied Crypto Aps, All rights reserved </small>
 * </p>
 * @author Jens Bo Friis, bofriis@gmail.com
 *
 */
public final class Des {

	public static void cbc_encrypt(byte[] input, byte[] output, byte[] key,
			byte[] ivec, boolean encrypt) throws KrbException {

		Cipher cipher = null;

		try {
			cipher = Cipher.getInstance("DES/CBC/NoPadding");
		} catch (GeneralSecurityException e) {
			KrbException ke = new KrbException(KrbException.KRB_GENERAL_ERROR, "JCE provider may not be installed. "
					+ e.getMessage());
			ke.initCause(e);
			throw ke;
		}
		IvParameterSpec params = new IvParameterSpec(ivec);
		SecretKeySpec skSpec = new SecretKeySpec(key, "DES");
		try {
			SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
			SecretKey sk = (SecretKey) skSpec;
			if (encrypt)
				cipher.init(Cipher.ENCRYPT_MODE, sk, params);
			else
				cipher.init(Cipher.DECRYPT_MODE, sk, params);
			byte[] result;
			result = cipher.doFinal(input);
			System.arraycopy(result, 0, output, 0, result.length);
		} catch (GeneralSecurityException e) {
			KrbException ke = new KrbException(KrbException.KRB_GENERAL_ERROR, e.getMessage());
			ke.initCause(e);
			throw ke;
		}
	}

	
	
}
