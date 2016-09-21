package dk.appliedcrypto.spnego;

/**
 * 
 * <p>
 * <small>SPNEGO SSO<br>
 * Copyright(c), Applied Crypto Aps, All rights reserved </small>
 * </p>
 * @author Jens Bo Friis, bofriis@gmail.com
 *
 */
public class ETypeNull extends EType {
	public ETypeNull() {
		encType = ETYPE_NULL;
		encTypeName = "NULL";
	}

	/**
	 * data is not encrypted, just pass through
	 */
	public byte[] decrypt(EncryptionKey key, int messageType, byte[] cipher) throws KrbException {
		return cipher;
	}
	
	/**
	 * data is not encrypted, just pass through
	 */
	public byte[] encrypt(EncryptionKey key, int messageType, byte[] plaintext) throws KrbException {
		return plaintext;
	}
}
