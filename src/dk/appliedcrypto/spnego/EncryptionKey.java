/*
 * $Id: EncryptionKey.java,v 1.7 2012-11-21 12:52:08 bofriis Exp $
 */
package dk.appliedcrypto.spnego;

import java.io.IOException;
import java.security.GeneralSecurityException;

import javax.security.auth.kerberos.KerberosKey;
import javax.security.auth.kerberos.KerberosPrincipal;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * http://www.faqs.org/rfcs/rfc1510.html
 * 
 * <p>
 * The sequence below shows the encoding of an encryption key: <br>
 * EncryptionKey ::= SEQUENCE {<br>
 * keytype[0] INTEGER, <br>
 * keyvalue[1] OCTET STRING <br>
 * <br>
 * <p>
 * keytype This field specifies the type of encryption key that follows in the
 * keyvalue field. It will almost always correspond to the encryption algorithm
 * used to generate the EncryptedData, though more than one algorithm may use
 * the same type of key (the mapping is many to one). This might happen, for
 * example, if the encryption algorithm uses an alternate checksum algorithm for
 * an integrity check, or a different chaining mechanism.
 * <p>
 * keyvalue This field contains the key itself, encoded as an octet string.
 * <p>
 * All negative values for the encryption key type are reserved for local use.
 * All non-negative values are reserved for officially assigned type fields and
 * interpretations.
 * 
 * <p>
 * <small>SPNEGO SSO<br>
 * Copyright(c), Applied Crypto Aps, All rights reserved </small>
 * </p>
 * @author Jens Bo Friis, bofriis@gmail.com
 */
public class EncryptionKey {
	private static Log LOG = LogFactory.getLog("EncryptionKey");

	int keyType = 0;

	byte[] keyValue = new byte[] {};

	int vno = -1; // key version number. if this is -1, the key version number
					// was not specified

	public int getKeyType() {
		return keyType;
	}

	public int getKeyVno() {
		return vno;
	}

	public byte[] getKeyValue() {
		return keyValue;
	}

	/**
	 * ANS.1 parser
	 * 
	 * @param dis
	 * @throws IOException
	 */
	void parse(DerInputStream dis) throws IOException {
		ASN1Object[] dvs = (ASN1Object[]) dis.getSequence(2);
		for (int i = 0; i < dvs.length; i++) {
			switch (((DERTaggedObject) dvs[i]).getTagNo()) {
			case 0: // keytype[0] INTEGER
				keyType = ASN1Integer.getInstance(((DERTaggedObject) dvs[i]).getObject()).getValue().intValue();
				break;
			case 1: // keyvalue[1] OCTET STRING
				keyValue = DEROctetString.getInstance(((DERTaggedObject) dvs[i]).getObject()).getOctets();
				break;
			default:
				LOG.error("unknown tag:" + (((DERTaggedObject) dvs[i]).getTagNo() & (byte) 0x1F));
			}
		}
	}

	/**
	 * Constructor
	 * 
	 * @param bytes
	 *            encoded EncryptionKey
	 * @throws IOException
	 *             if either a parsing error occurs
	 */
	EncryptionKey(byte[] bytes) throws IOException {
		this(new DerInputStream(bytes));
	}

	/**
	 * Empty constructor
	 */
	EncryptionKey(int keyType, String hex) {
		if (hex.startsWith("0x"))
			hex = hex.substring(2);
		this.keyValue = new byte[hex.length() / 2];
		for (int i = 0; i < hex.length(); i++, i++) {
			keyValue[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
		}
		this.keyType = keyType;
	}

	/**
     */
	public EncryptionKey(int keyType, byte[] keyValue) {
		this.keyValue = keyValue;
		this.keyType = keyType;
	}

	/**
     */
	EncryptionKey(int keyType, byte[] keyValue, int vno) {
		this.keyValue = keyValue;
		this.keyType = keyType;
		this.vno = vno;
	}

	/**
	 * Construct an EncryptionKey object from ASN.1
	 * 
	 * @param dis
	 *            -- DER input stream
	 * @throws IOException
	 */
	EncryptionKey(DerInputStream dis) throws IOException {
		parse(dis);
	}

	/**
	 * Construct an EncryptionKey object from JGSS Kerberos Key object
	 * 
	 * @param KerberosKey
	 *            -- the kerberos key
	 * @throws IOException
	 */
	EncryptionKey(KerberosKey key) {
		this.keyValue = key.getEncoded();
		this.keyType = key.getKeyType();
		this.vno = key.getVersionNumber();
	}

	/**
	 * Construct an EncryptionKey object from ASN.1
	 * 
	 * @param dv
	 *            -- DER value
	 * @throws IOException
	 */
//	EncryptionKey(DerValue dv) throws IOException {
//		parse(dv.getData());
//	}

	/**
	 * Get the encoded encryption key object
	 * 
	 * @return EncryptionKey as ASN.1 encoded byte[]
	 * @throws IOException
	 */
	byte[] getEncoded() throws IOException {
		DerOutputStream dos = new DerOutputStream();
		byte[] baKeyType = new DerOutputStream().putInteger(keyType).toByteArray();
		byte[] baKeyValue = new DerOutputStream().putOctetString(keyValue).toByteArray();
		DERTaggedObject[] tags = new DERTaggedObject[2];
		tags[0] = new DERTaggedObject(0, new ASN1Integer(keyType));
		tags[1] = new DERTaggedObject(1, new DEROctetString(keyValue));
		dos.putSequence(tags);
		return dos.toByteArray();
	}

	/**
	 * Get encryption key from crendetials
	 * 
	 * @param princ
	 * @param password
	 * @param salt
	 * @param enctype
	 * @return an EncryptionKey
	 * @throws GeneralSecurityException
	 */
	public static EncryptionKey getEncryptionKey(PrincipalName princ, char[] password, byte[] salt, int enctype) throws GeneralSecurityException {
		KerberosKey kkey = getKerberosKey(princ, password, salt, enctype);
		return new EncryptionKey(kkey);
	}

	/**
	 * Return the kerberos key
	 * 
	 * @param principalName
	 * @param password
	 * @param enctype
	 *            , if =0, use the default enc type defined in krb5 config.
	 * @return
	 * @throws GeneralSecurityException
	 */
	public static KerberosKey getKerberosKey(PrincipalName princ, char[] password, byte[] salt, int enctype) throws GeneralSecurityException {

		EncryptionKey encKey = null;
//		if (enctype == 0)
//			enctype = Config.getInstance().getDefaultEncType()[0];

		if (enctype == EType.ETYPE_AES128_CTS_HMAC_SHA1_96) {
			int keyType = enctype;
			AES_SHA1 aes = new AES_SHA1(128);

			if (salt == null)
				salt = princ.getSalt();
			byte[] keyBytes = aes.stringToKey(password, salt, null, -1);
			;
			KerberosKey kerbKey = new KerberosKey(new KerberosPrincipal(princ.toString()), keyBytes, keyType, 1);
			encKey = new dk.appliedcrypto.spnego.EncryptionKey(kerbKey);
		}

		if (enctype == EType.ETYPE_AES256_CTS_HMAC_SHA1_96) {
			int keyType = enctype;
			AES_SHA1 aes = new AES_SHA1(256);
			// salt = TEST2008.NETHTTPwebserver.test2008.net
			// salt = REALM | SPN

			if (salt == null)
				salt = princ.getSalt();
			byte[] keyBytes = aes.stringToKey(password, salt, null, -1);
			;
			KerberosKey kerbKey = new KerberosKey(new KerberosPrincipal(princ.toString()), keyBytes, keyType, 1);
			encKey = new dk.appliedcrypto.spnego.EncryptionKey(kerbKey);
		}

		if (enctype == 23) {
			/*
			 * 
			 * @param principal the principal that this secret key belongs to
			 * 
			 * @param keyBytes the raw bytes for the secret key @param keyType
			 * the key type for the secret key as defined by the Kerberos
			 * protocol specification. @param versionNum the version number of
			 * this secret key
			 */
			int keyType = enctype;
			byte[] keyBytes = RC4_HMAC.String2Key(password);
			KerberosKey kerbKey = new KerberosKey(new KerberosPrincipal(princ.toString()), keyBytes, keyType, 1);
			encKey = new dk.appliedcrypto.spnego.EncryptionKey(kerbKey);

		}
		if (enctype == 3 || enctype == 2 || enctype == 1) {
			/*
			 * NOTE: the key version number is default =0. Use /kvno 1 for Win2K
			 * compat.
			 */
			KerberosKey kerbKey = new KerberosKey(new KerberosPrincipal(princ.toString()), password, "DES");
			encKey = new EncryptionKey(kerbKey);
			encKey.vno = 1;
		}
		if (encKey == null)
			throw new GeneralSecurityException("could not generate encryption key, unsupported encryption type " + enctype);
		return encKey.toKerberosKey(new KerberosPrincipal(princ.toString()));
	}

	public KerberosKey toKerberosKey(KerberosPrincipal kerbPrinc) {
		KerberosKey kerbKey = new KerberosKey(kerbPrinc, this.keyValue, this.keyType, (this.vno == -1) ? (0) : (this.vno));
		return kerbKey;
	}
	
	public static EncryptionKey toEncryptionKey(KerberosKey kkey) {
		return new EncryptionKey(kkey.getKeyType(), kkey.getEncoded(), kkey.getVersionNumber());
	}

	public static EncryptionKey[] toEncryptionKey(KerberosKey[] kkeys) {
		EncryptionKey[] keys = new EncryptionKey[kkeys.length];
		for (int i=0; i<kkeys.length; i++)
			keys[i] = toEncryptionKey(kkeys[i]);
		return keys;
	}

	/**
	 * Return encryption keys in keytab that matches the spn. if
	 * <code>enctype==0</code> return all keys, otherwise return only the single
	 * key that matches
	 * 
	 * @param spn
	 * @param enctype
	 * @param keytabfile
	 * @return array of encryption keys
	 * @throws IOException
	 */
	public static KerberosKey[] getEncryptionKeys(String spn, String keytabfile) throws KrbException, IOException {

//		if (keytabfile == null)
//			keytabfile = Config.getInstance().getDefaultKeytab();

		KerberosPrincipal kerbPrinc = new KerberosPrincipal(spn, PrincipalName.KRB_NT_PRINCIPAL);
		KeyTab keytab = KeyTab.getInstance(keytabfile);
		try {
			return keytab.getKeys(spn, 0, 0);
		} catch (KrbException e) {
			return keytab.getKeys(new Realm(kerbPrinc.getRealm()), 0);
		}
	}

	public String toString() {
		StringBuffer sb = new StringBuffer();
		sb.append(" etype 0x" + HexDump.tohex(keyType, ((keyType < 0x10) ? (1) : (2))));
		sb.append(" (" + EType.getETypeName(keyType) + ")");
		sb.append(" (vno:" + vno + ")");
		sb.append(" keylength " + keyValue.length);
		sb.append(" (" + HexDump.hex(keyValue) + ")");
		return sb.toString();
	}
}