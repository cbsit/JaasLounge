package dk.appliedcrypto.spnego;

import java.security.MessageDigest;

/**
 *  * <p>
 * <small>SPNEGO SSO<br>
 * Copyright(c), Applied Crypto Aps, All rights reserved </small>
 * </p>
 * @author Jens Bo Friis, bofriis@gmail.com
 *
 */
public final class DesCbcMd5 extends EType {
	
	private static int CHECKSUM_SIZE = 16;
	private static int CONFOUNDER_SIZE = 8;
	
	public DesCbcMd5() {
		encType = ETYPE_DES_CBC_MD5;
		/* "DES-CBC-MD5" */
		String msg = "DES-CBC-MD5";
		encTypeName = msg;
	}

	public byte[] encrypt(EncryptionKey key, int messageType, byte[] cipher) throws KrbException {
		throw new KrbException(KrbException.KRB_GENERAL_ERROR, "not implemented");
	}

	
	public static byte[] decrypt(byte[] cipher, byte[] key, byte[] ivec, int usage) throws KrbException {

		try {
			byte[] data = new byte[cipher.length];
			Des.cbc_encrypt(cipher, data, key, ivec, false);

			// data contains a checksum, confounder, and raw data
			byte[] ddata = new byte[data.length - CHECKSUM_SIZE - CONFOUNDER_SIZE];
			System.arraycopy(data, CHECKSUM_SIZE + CONFOUNDER_SIZE, ddata, 0, ddata.length);

			byte[] dconfounder = new byte[CONFOUNDER_SIZE];
			System.arraycopy(data, 0, dconfounder, 0, dconfounder.length);

			byte[] dchecksum = new byte[CHECKSUM_SIZE];
			System.arraycopy(data, CONFOUNDER_SIZE, dchecksum, 0, dchecksum.length);

			// System.out.println(HexDump.xdump(dchecksum));

			// byte[] checksum = checksum(RC4_HMAC.concat(dconfounder, data));
			// System.out.println(HexDump.xdump(checksum));
			/*
			 * could do some checksumming, but integrity checking is done at
			 * higher level.
			 */
			return ddata;
		} catch (KrbException e) {
			throw e;
		}
	}

	public byte[] decrypt(EncryptionKey key, int messageType, byte[] cipher) throws KrbException {
		return decrypt(cipher, key.getKeyValue(), key.getKeyValue(), messageType);
	}

	private static byte[] checksum(byte[] data) throws Exception {
		MessageDigest md5 = null;
		md5 = MessageDigest.getInstance("MD5");
		md5.update(data);
		return (md5.digest());
	}
}
