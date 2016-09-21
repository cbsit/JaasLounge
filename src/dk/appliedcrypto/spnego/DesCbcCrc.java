package dk.appliedcrypto.spnego;

/**
 * +-----------+----------+---------+-----+ 
 * |confounder | checksum | msg-seq |pad 
 * | +-----------+----------+---------+-----+
 * 
 * <p>
 * <small>SPNEGO SSO<br>
 * Copyright(c), Applied Crypto Aps, All rights reserved </small>
 * </p>
 * @author Jens Bo Friis, bofriis@gmail.com
 * 
 */
public class DesCbcCrc extends EType {

	private static int CHECKSUM_SIZE = 4;

	private static int CONFOUNDER_SIZE = 8;

	public DesCbcCrc() {
		encType = ETYPE_DES_CBC_CRC;
		/* "DES-CBC-CRC" */
		String msg = "DES-CBC-CRC";
		encTypeName = msg;
	}

	public byte[] encrypt(EncryptionKey key, int messageType, byte[] cipher) throws KrbException {
		throw new KrbException(KrbException.KRB_GENERAL_ERROR, "not implemented");
	}

	public static byte[] decrypt(byte[] cipher, byte[] key, byte[] ivec, int usage) throws KrbException {

		byte[] data = new byte[cipher.length];
		Des.cbc_encrypt(cipher, data, key, ivec, false);

		// data contains a checksum, confounder, and raw data
		byte[] ddata = new byte[data.length - CONFOUNDER_SIZE - CHECKSUM_SIZE];
		System.arraycopy(data, CONFOUNDER_SIZE + CHECKSUM_SIZE, ddata, 0, ddata.length);
		byte[] dconfounder = new byte[CONFOUNDER_SIZE];
		System.arraycopy(data, 0, dconfounder, 0, dconfounder.length);
		byte[] dchecksum = new byte[CHECKSUM_SIZE];
		System.arraycopy(data, CONFOUNDER_SIZE, dchecksum, 0, dchecksum.length);

		// System.out.println(HexDump.xdump(ddata));

		/*
		 * could do some checksumming, but integrity checking is done at higher
		 * level.
		 */

		return ddata;
	}

	public byte[] decrypt(EncryptionKey key, int messageType, byte[] cipher) throws KrbException {
		return decrypt(cipher, key.getKeyValue(), key.getKeyValue(), messageType);
	}
}
