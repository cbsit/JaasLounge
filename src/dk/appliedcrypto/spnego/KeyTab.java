package dk.appliedcrypto.spnego;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Vector;

import javax.security.auth.kerberos.KerberosKey;
import javax.security.auth.kerberos.KerberosPrincipal;

/**
 * (c) Applied Crypto
 * 
 * 
 * The Kerberos Keytab Binary File Format Copyright (C) 2006 Michael B Allen
 * <mba2000 ioplex.com> http://www.ioplex.com/utilities/keytab.txt Last updated:
 * Fri May 5 13:39:40 EDT 2006
 * 
 * The MIT keytab binary format is not a standard format, nor is it documented
 * anywhere in detail. The format has evolved and may continue to. It is however
 * understood by several Kerberos implementations including Heimdal and of
 * course MIT and keytab files are created by the ktpass.exe utility from
 * Windows. So it has established itself as the defacto format for storing
 * Kerberos keys.
 * 
 * The following C-like structure definitions illustrate the MIT keytab file
 * format. All values are in network byte order. All text is ASCII.
 * 
 * <pre>
 *  keytab { uint16_t file_format_version; // 0x502
 *  keytab_entry entries[*];
 *  };
 * 
 *  keytab_entry {
 *  int32_t size;
 *  uint16_t num_components;    // sub 1 if version 0x501
 *  counted_octet_string realm;
 *  counted_octet_string components[num_components];
 *  uint32_t name_type;   // not present if version 0x501
 *  uint32_t timestamp;
 *  uint8_t vno8;
 *  keyblock key;
 *  uint32_t vno; // only present if &gt;= 4 bytes left in entry 
 *  };
 * 
 *  counted_octet_string {
 *  uint16_t length;
 *  uint8_t data[length];
 *  };
 * 
 *  keyblock {
 *  uint16_t type;
 *  counted_octet_string;
 *  };
 * </pre>
 * 
 * The keytab file format begins with the 16 bit file_format_version which at
 * the time this document was authored is 0x502. The format of older keytabs is
 * described at the end of this document.
 * 
 * The file_format_version is immediately followed by an array of keytab_entry
 * structures which are prefixed with a 32 bit size indicating the number of
 * bytes that follow in the entry. Note that the size should be evaluated as
 * signed. This is because a negative value indicates that the entry is in fact
 * empty (e.g. it has been deleted) and that the negative value of that negative
 * value (which is of course a positive value) is the offset to the next
 * keytab_entry. Based on these size values alone the entire keytab file can be
 * traversed.
 * 
 * The size is followed by a 16 bit num_components field indicating the number
 * of counted_octet_string components in the components array.
 * 
 * The num_components field is followed by a counted_octet_string representing
 * the realm of the principal.
 * 
 * A counted_octet_string is simply an array of bytes prefixed with a 16 bit
 * length. For the realm and name components, the counted_octet_string bytes are
 * ASCII encoded text with no zero terminator.
 * 
 * Following the realm is the components array that represents the name of the
 * principal. The text of these components may be joined with slashs to
 * construct the typical SPN representation. For example, the service principal
 * HTTP/www.foo.net@FOO.NET would consist of name components "HTTP" followed by
 * "www.foo.net".
 * 
 * Following the components array is the 32 bit name_type (e.g. 1 is
 * KRB5_NT_PRINCIPAL, 2 is KRB5_NT_SRV_INST, 5 is KRB5_NT_UID, etc). In practice
 * the name_type is almost certainly 1 meaning KRB5_NT_PRINCIPAL.
 * 
 * The 32 bit timestamp indicates the time the key was established for that
 * principal. The value represents the number of seconds since Jan 1, 1970.
 * 
 * The 8 bit vno8 field is the version number of the key. This value is
 * overridden by the 32 bit vno field if it is present.
 * 
 * The keyblock structure consists of a 16 bit value indicating the keytype
 * (e.g. 3 is des-cbc-md5, 23 is arcfour-hmac-md5, 16 is des3-cbc-sha1, etc).
 * This is followed by a counted_octet_string containing the key.
 * 
 * The last field of the keytab_entry structure is optional. If the size of the
 * keytab_entry indicates that there are at least 4 bytes remaining, a 32 bit
 * value representing the key version number is present. This value supersedes
 * the 8 bit vno8 value preceeding the keyblock.
 * 
 * Older keytabs with a file_format_version of 0x501 are different in three
 * ways:
 * 
 * 1) All integers are in host byte order [1]. 2) The num_components field is 1
 * too large (i.e. after decoding, decrement by 1). 3) The 32 bit name_type
 * field is not present.
 * 
 * [1] The file_format_version field should really be treated as two separate 8
 * bit quantities representing the major and minor version number respectively.
 * 
 * Permission to copy, modify, and distribute this document, with or without
 * modification, for any purpose and without fee or royalty is hereby granted,
 * provided that you include this copyright notice in ALL copies of the document
 * or portions thereof, including modifications.
 * 
 * 
 * <p>
 * <small>SPNEGO SSO<br>
 * Copyright(c), Applied Crypto Aps, All rights reserved </small>
 * </p>
 * @author Jens Bo Friis, bofriis@gmail.com
 * 
 */
public final class KeyTab {
	private static Log LOG = LogFactory.getLog("KeyTab");

	int file_format_version = 0x502;

	ArrayList<KeyTabEntry> entries = new ArrayList<KeyTabEntry>();
	
	private static Hashtable<String,KeyTab> keytabFiles = new Hashtable<String,KeyTab>();
	
	public static boolean useKeyTabFileCaching = true;

	public void read(InputStream in) throws IOException {
		file_format_version = keytabVersion(in);
		if (file_format_version != 0x502)
			throw new IOException("Keytab file version " + file_format_version
					+ " is not supported.");
		while (in.available() > 0) {
			KeyTabEntry entry = new KeyTabEntry();
			entry.read(in, file_format_version);
			entries.add(entry);
		}
	}

	public void write(OutputStream out) throws IOException {
		keytabVersion(out, 0x502);

		Iterator<KeyTabEntry> it = entries.iterator();
		while (it.hasNext()) {
			((KeyTabEntry) it.next()).write(out);
		}
	}

	static String readOctetString(InputStream in) throws IOException {
		int len = read16(in);
		byte[] bytes = new byte[len];
		in.read(bytes, 0, len);
		return new String(bytes, 0, len);
	}

	static void writeOctetString(OutputStream out, String string)
			throws IOException {
		byte[] bytes = string.getBytes();
		int len = bytes.length;
		write16(out, len);
		out.write(bytes, 0, len);
	}

	static void write32(OutputStream out, int num) throws IOException {
		byte[] bytes = new byte[4];
		bytes[0] = (byte) ((num & 0xff000000) >> 24 & 0xff);
		bytes[1] = (byte) ((num & 0x00ff0000) >> 16 & 0xff);
		bytes[2] = (byte) ((num & 0x0000ff00) >> 8 & 0xff);
		bytes[3] = (byte) (num & 0xff);
		out.write(bytes, 0, 4);
	}

	static void write16(OutputStream out, int num) throws IOException {
		byte[] bytes = new byte[2];
		bytes[0] = (byte) ((num & 0xff00) >> 8 & 0xff);
		bytes[1] = (byte) (num & 0xff);
		out.write(bytes, 0, 2);
	}

	static void write8(OutputStream out, int num) throws IOException {
		out.write(num & 0xff);
	}

	private static int read(InputStream in, int num) throws IOException {
		byte[] bytes = new byte[num];
		in.read(bytes, 0, num);
		int result = 0;
		for (int i = 0; i < num; i++) {
			result |= (bytes[i] & 0xff) << (num - i - 1) * 8;
		}
		return result;
	}

	static int read16(InputStream in) throws IOException {
		return read(in, 2);
	}

	static int read8(InputStream in) throws IOException {
		return read(in, 1);
	}

	static int read32(InputStream in) throws IOException {
		return read(in, 4);
	}

	private static int keytabVersion(InputStream in) throws IOException {
		return read16(in);
	}

	private static void keytabVersion(OutputStream out, int version) throws IOException {
		write16(out, version);
	}

//	private static int keytabEntryLength(InputStream in) throws IOException {
//		return read32(in);
//	}
	
	/**
	 * Read keytab
	 * @param keytabFileName
	 * @return
	 * @throws IOException
	 */
	public synchronized static KeyTab getInstance(String keytabFileName) throws IOException {
		if (keytabFiles.get(keytabFileName)!=null && useKeyTabFileCaching) {
			return (KeyTab)keytabFiles.get(keytabFileName);
		}
		KeyTab keytab = new KeyTab();
		InputStream fis = null;
		try {
			fis = new BufferedInputStream(new FileInputStream(keytabFileName));
			keytab.read(fis);
			keytabFiles.put(keytabFileName, keytab);
			return keytab;
		} catch(FileNotFoundException e) {
			LOG.error("could not read " + new File(keytabFileName).getAbsolutePath());
			throw e;
		} catch(IOException e) {
			LOG.error("could not read " + keytabFileName);
			throw e;
		} finally {
			if (fis!=null)
				fis.close();
			LOG.debug("keytab: " + keytab);
		}
	}

	
	/**
	 * Return the encryption keys.
	 * @param princ
	 * @param enctype if 0, return all keys of any type otherwise return only the specified key
	 * @param keyVno 
	 * @return array of 
	 */
	public KerberosKey[] getKeys(String princ, int enctype, int keyVno) throws KrbException {
		Vector<KerberosKey> list = new Vector<KerberosKey>();
		Iterator<KeyTabEntry> it = entries.iterator();
		while (it.hasNext()) {
			KeyTabEntry entry = (KeyTabEntry) it.next();
			if (entry.principal.toString().equalsIgnoreCase(princ) && (enctype==0 || enctype==entry.key.keyType))
				if (keyVno == 0 || keyVno == entry.key.vno)  {
					KerberosKey kk = new KerberosKey(new KerberosPrincipal(entry.principal.toString()), entry.key.keyValue, entry.key.keyType, entry.key.vno);
					list.add(kk);
				}
		}
		if (list.size()==0) {
			it = entries.iterator();
			while (it.hasNext()) {
				KeyTabEntry entry = (KeyTabEntry) it.next();
				if (entry.principal.toString().equalsIgnoreCase("*@*") && (enctype==0 || enctype==entry.key.keyType))
					if (keyVno == 0 || keyVno == entry.key.vno)  {
						KerberosKey kk = new KerberosKey(new KerberosPrincipal(princ), entry.key.keyValue, entry.key.keyType, entry.key.vno);
						KerberosKey[] keys = new KerberosKey[]{kk};
						return keys;
					}
			}
			LOG.debug("could not find key matching " + princ + " encType:" + EType.getETypeName(enctype));
			throw new KrbException(KrbException.KRB_AP_ERR_NOKEY, "No suitable encryption key of type " + EType.getETypeName(enctype));
		}
		KerberosKey[] keys = new KerberosKey[list.size()];
		list.copyInto(keys);
		return keys;
	}
	
	
	/**
	 * Return the array of KerberosKey.
	 * @return array of 
	 */
	public KerberosKey[] getKeys() throws KrbException{
		Vector<KerberosKey> list = new Vector<KerberosKey>();
		Iterator<KeyTabEntry> it = entries.iterator();
		while (it.hasNext()) {
			KeyTabEntry entry = (KeyTabEntry) it.next();
			KerberosKey kk = new KerberosKey(new KerberosPrincipal(entry.principal.toString()), entry.key.keyValue, entry.key.keyType, entry.key.vno);
			list.add(kk);
		}
		KerberosKey[] keys = new KerberosKey[list.size()];
		list.copyInto(keys);
		return keys;
	}
	/**
	 * Return the encryption keys.
	 * @param princ
	 * @param enctype if 0, return all keys of any type otherwise return only the specified key
	 * @return array of 
	 */
	public KerberosKey[] getKeys(Realm realm, int enctype) throws KrbException{
		Vector<KerberosKey> list = new Vector<KerberosKey>();
		Iterator<KeyTabEntry> it = entries.iterator();
		while (it.hasNext()) {
			KeyTabEntry entry = (KeyTabEntry) it.next();
			if (entry.principal.getRealmString().equals(realm.toString()) && (enctype==0 || enctype==entry.key.keyType)) {
				KerberosPrincipal kp = new KerberosPrincipal(entry.principal.toString(), PrincipalName.KRB_NT_PRINCIPAL);
				KerberosKey kk = new KerberosKey(kp, entry.key.keyValue, entry.key.keyType, entry.key.vno );
				list.add(kk);
			}
		}
		if (list.size()==0) {
			LOG.debug("could not find key matching " + realm + " encType:" + EType.getETypeName(enctype));
			LOG.debug("keytab:"+toString());
			throw new KrbException(KrbException.KRB_AP_ERR_NOKEY, "No suitable encryption key of type " + EType.getETypeName(enctype));
		}
		KerberosKey[] keys = new KerberosKey[list.size()];
		list.copyInto(keys);
		return keys;
	}

	public String toString() {
		StringBuffer sb = new StringBuffer();
		sb.append("Keytab version: 0x"
				+ HexDump.tohex(this.file_format_version, 3) + "\r\n");
		Iterator<KeyTabEntry> it = entries.iterator();
		while (it.hasNext()) {
			KeyTabEntry entry = (KeyTabEntry) it.next();
			sb.append(entry.toString() + "\r\n");
		}
		return sb.toString();
	}

	void addEntry(KeyTabEntry entry) {
		entries.add(entry);
	}

	
	/**
	 * 
	 * @param spn
	 * @param princ
	 * @param pass
	 * @param enctype
	 * @throws Exception
	 */
	public void addKeyTabEntry(String princ, char[] pass, int enctype) throws Exception {
		KeyTabEntry entry = new KeyTabEntry();

		PrincipalName principal = new PrincipalName(
				princ, PrincipalName.KRB_NT_PRINCIPAL);
	
		if (principal.getRealmString()==null)
			throw new IllegalArgumentException("service principal name must include REALM e.g. HTTP/webserver.test.net@TEST.NET");
		entry.principal = principal;

		byte[] salt = null;
		
		KerberosKey kkey = EncryptionKey.getKerberosKey(principal, pass, salt, enctype);
		EncryptionKey key = new EncryptionKey(kkey);

		entry.key = key;
		entry.key.keyType = enctype;

		entry.timestamp = System.currentTimeMillis();
		
		addEntry(entry);
	}
	
	public KeyTab addKeyTabEntry(String princ, int keytype, byte[] keyvalue) throws IOException  {
		KeyTabEntry entry = new KeyTabEntry();

		PrincipalName principal = new PrincipalName(
				princ, PrincipalName.KRB_NT_PRINCIPAL);
	
//		if (principal.getRealmString()==null)
//			throw new IllegalArgumentException("service principal name must include REALM e.g. HTTP/webserver.test.net@TEST.NET");
		entry.principal = principal;
		
		EncryptionKey key = new EncryptionKey(keytype, keyvalue);

		entry.key = key;
		entry.key.keyType = keytype;

		entry.timestamp = System.currentTimeMillis();
		
		addEntry(entry);
		return this;
	}


	
	/**
	 * use default service=HOST
	 * @param service
	 * @param hostname
	 * @param realm
	 * @param princ
	 * @param pass
	 * @param enctype
	 * @throws Exception
	 */
	public void addKeyTabEntry(String service, String hostname, String realm, char[] pass, int enctype) throws Exception {
		KeyTabEntry entry = new KeyTabEntry();

		PrincipalName principal = new PrincipalName(
				new String[] { service, hostname }, PrincipalName.KRB_NT_PRINCIPAL);
	
		principal.setRealm(new Realm(realm));

		entry.principal = principal;

		byte[] salt = null;
		
		KerberosKey kkey = EncryptionKey.getKerberosKey(principal, pass, salt, enctype);
		EncryptionKey key = new EncryptionKey(kkey);

		entry.key = key;

		entry.timestamp = System.currentTimeMillis();
		
		addEntry(entry);
	}

	public String getDefaultSPN(String realm) throws KrbException {
		Iterator<KeyTabEntry> it = entries.iterator();
		while (it.hasNext()) {
			KeyTabEntry entry = (KeyTabEntry) it.next();
			if (entry.principal.getRealmString().equals(realm))
				return entry.principal.toString();
		}
		throw new KrbException(KrbException.KRB_AP_ERR_NOKEY, "Could not find encryption key for realm " + realm);
	}
	
	public String getInfo() {
		return "Keytab, entries: " + entries.size();
	}
}
