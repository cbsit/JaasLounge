/*
 * $Id: EType.java,v 1.7 2009-01-18 19:53:39 bofriis Exp $
 */
package dk.appliedcrypto.spnego;

import java.security.InvalidParameterException;


/**
 * Standard encryption types
 * 
 * <p>
 * <small>SPNEGO SSO<br>
 * Copyright(c), Applied Crypto Aps, All rights reserved </small>
 * </p>
 * @author Jens Bo Friis, bofriis@gmail.com
 */
abstract class EType {

	private static Log LOG = LogFactory.getLog("EType");

	public static final int KU_UNKNOWN = 0;

	public static final int KU_PA_ENC_TS = 1;

	public static final int KU_TICKET = 2;

	public static final int KU_ENC_AS_REP_PART = 3;

	public static final int KU_TGS_REQ_AUTH_DATA_SESSKEY = 4;

	public static final int KU_TGS_REQ_AUTH_DATA_SUBKEY = 5;

	public static final int KU_PA_TGS_REQ_CKSUM = 6;

	public static final int KU_PA_TGS_REQ_AUTHENTICATOR = 7;

	public static final int KU_ENC_TGS_REP_PART_SESSKEY = 8;

	public static final int KU_ENC_TGS_REP_PART_SUBKEY = 9;

	public static final int KU_AUTHENTICATOR_CKSUM = 10;

	public static final int KU_AP_REQ_AUTHENTICATOR = 11;

	public static final int KU_ENC_AP_REP_PART = 12;

	public static final int KU_ENC_KRB_PRIV_PART = 13;

	public static final int KU_ENC_KRB_CRED_PART = 14;

	public static final int KU_KRB_SAFE_CKSUM = 15;

	public static final int KU_AD_KDC_ISSUED_CKSUM = 19;

	public static final int ETYPE_NULL = 0; // 1 0 0

	public static final int ETYPE_DES_CBC_CRC = 1; // 8 4 8

	// public static final int ETYPE_DES_CBC_MD4 = 2; // 8 0 8

	public static final int ETYPE_DES_CBC_MD5 = 3; // 8 0 8

	public static final int ETYPE_RC4_HMAC = 23; // 23

	public static final int ETYPE_AES128_CTS_HMAC_SHA1_96 = 17;

	public static final int ETYPE_AES256_CTS_HMAC_SHA1_96 = 18;

	public static final int CHECKSUM_TYPE_HMAC_SHA1_96_AES256 = 16;

	public static final int CHECKSUM_TYPE_HMAC_SHA1_96_AES128 = 15;

	public static final int ETYPE_RC4_HMAC_EXP = 24; // 24

	// draft-ietf-krb-wg-crypto-07.txt
	// public static final int ETYPE_DES3_CBC_HMAC_SHA1_KD = 16; // 8 0 8

	protected String encTypeName = null;

	protected int encType = ETYPE_NULL;

	/**
	 * Return encryption algorithm, which is used when KerberosKey is generated
	 * 
	 * @param etype
	 *            type 1,3, 23, 24
	 * @return
	 */
	// public static String getEncAlgorithm(int etype) {
	// switch (etype) {
	// case ETYPE_DES_CBC_CRC:
	// return "DES";
	// case ETYPE_DES_CBC_MD5:
	// return "DES";
	// case ETYPE_RC4_HMAC:
	// return "RC4-HMAC";
	// // case ETYPE_RC4_HMAC_EXP:
	// // return "RC4-HMAC";
	// default:
	// throw new InvalidParameterException("unsupported paramter " + etype);
	// }
	// }
	public static String getETypeName(int etype) {
		switch (etype) {
		case ETYPE_NULL:
			return "NULL";
		case ETYPE_DES_CBC_CRC:
			return "DES-CBC-CRC";
			// case ETYPE_DES_CBC_MD4:
			// return "DES-CBC-MD4";
		case ETYPE_DES_CBC_MD5:
			return "DES-CBC-MD5";
		case ETYPE_RC4_HMAC:
			return "RC4-HMAC";
		case ETYPE_RC4_HMAC_EXP:
			return "RC4-HMAC-EXP";
		case ETYPE_AES128_CTS_HMAC_SHA1_96:
			return "AES128-CTS-HMAC-SHA1-96";
		case ETYPE_AES256_CTS_HMAC_SHA1_96:
			return "AES256-CTS-HMAC-SHA1-96";
		case -133:
			return "RC4-HMAC-OLD";
		case -128:
			return "RC4-HMAC-OLD-EXP";
		default:
			return "UNSUPPORTED ETYPE " + etype;
		}
	}

	public static int getEtype(String sEType) {
		if (sEType.equalsIgnoreCase("des-cbc-crc")) {
			return ETYPE_DES_CBC_CRC;
		}
		if (sEType.equalsIgnoreCase("des-cbc-md5")) {
			return ETYPE_DES_CBC_MD5;
		}
		if (sEType.equalsIgnoreCase("rc4-hmac") || sEType.equalsIgnoreCase("rc4-hmac-nt")) {
			return ETYPE_RC4_HMAC;
		}
		if (sEType.equalsIgnoreCase("AES256-SHA1")) {
			return ETYPE_AES256_CTS_HMAC_SHA1_96;
		}
		if (sEType.equalsIgnoreCase("AES128-SHA1")) {
			return ETYPE_AES128_CTS_HMAC_SHA1_96;
		}
		// if (sEType.equalsIgnoreCase("rc4-hmac-exp")) {
		// return ETYPE_RC4_HMAC_EXP;
		// }
		throw new InvalidParameterException("unsupported parameter " + sEType);
	}

	static EType getInstance(int encType) {
		switch (encType) {
		case ETYPE_NULL:
			return new ETypeNull();
		case ETYPE_DES_CBC_CRC:
			return new DesCbcCrc();
			// case ETYPE_DES_CBC_MD4:
			// return "DES-CBC-MD4";
		case ETYPE_DES_CBC_MD5:
			return new DesCbcMd5();
		case ETYPE_RC4_HMAC:
			return new RC4_HMAC();
		case ETYPE_AES128_CTS_HMAC_SHA1_96:
			return new AES_SHA1(128);
		case ETYPE_AES256_CTS_HMAC_SHA1_96:
			return new AES_SHA1(256);
			// case ETYPE_RC4_HMAC_EXP:
			// return "RC4-HMAC-EXP";
		default:
			throw new InvalidParameterException("unsupported parameter " + encType);
		}

	}

	public abstract byte[] encrypt(EncryptionKey key, int messageType, byte[] plaintext) throws KrbException;

	public abstract byte[] decrypt(EncryptionKey key, int messageType, byte[] cipher) throws KrbException;

}
