package dk.appliedcrypto.spnego;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * 
 * <pre>
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
 * </pre>
 * 
 * <p>
 * <small>SPNEGO SSO<br>
 * Copyright(c), Applied Crypto Aps, All rights reserved </small>
 * </p>
 * @author Jens Bo Friis, bofriis@gmail.com
 * 
 */
final class KeyTabEntry {

//	int size;

//	int num_components;

	// String realm;

	// String[] components;

	// int name_type;

	long timestamp;

	int vno8=255;

	EncryptionKey key;

	int vno=-1;

	PrincipalName principal;

	/**
	 * <pre>
	 *  keyblock {
	 *  uint16_t type;
	 *  counted_octet_string;
	 *  };
	 *  counted_octet_string {
	 *  uint16_t length;
	 *  uint8_t data[length];
	 *  };
	 * </pre>
	 * 
	 * @author bofriis
	 * 
	 */
	// class KeyBlock {
	// int type;
	//
	// int len;
	//
	// byte[] data;
	//
	// void read(InputStream in) throws IOException {
	// type = KeyTab.read16(in);
	// len = KeyTab.read16(in);
	// data = new byte[len];
	// in.read(data, 0, len);
	// }
	//
	// void write(OutputStream out) throws IOException {
	// KeyTab.write16(out, type);
	// KeyTab.write16(out, len);
	// out.write(data);
	// }
	// }
	// * int32_t size;
	// * uint16_t num_components; // sub 1 if version 0x501
	// * counted_octet_string realm;
	// * counted_octet_string components[num_components];
	// * uint32_t name_type; // not present if version 0x501
	// * uint32_t timestamp;
	// * uint8_t vno8;
	// * keyblock key;
	// * uint32_t vno; // only present if &gt;= 4 bytes left in entry
	public void read(InputStream in, int keytab_version) throws IOException {
		int size = KeyTab.read32(in);
		int bytesleft = in.available();
		int num_components = KeyTab.read16(in);
		if (keytab_version == 0x501)
			num_components--;
		String realm = KeyTab.readOctetString(in);
		String[] components = new String[num_components];
		for (int i = 0; i < num_components; i++) {
			components[i] = KeyTab.readOctetString(in);
		}
		int name_type = 0;
		if (keytab_version != 0x501) {
			name_type = KeyTab.read32(in);
		}
		principal = new PrincipalName(components, name_type);
		principal.setRealm(new Realm(realm));
		timestamp = KeyTab.read32(in)*1000;
		vno8 = KeyTab.read8(in);
		key = readEncryptionKey(in);
		int bytesleft1=in.available();
		if (bytesleft-bytesleft1-size>4)
			vno = KeyTab.read32(in);
	}

	static EncryptionKey readEncryptionKey(InputStream in) throws IOException {
		int type = KeyTab.read16(in);
		int len = KeyTab.read16(in);
		byte[] data = new byte[len];
		in.read(data, 0, len);
		return new EncryptionKey(type, data);
	}

	void writeEncryptionKey(OutputStream out, EncryptionKey key) throws IOException {
		KeyTab.write16(out, key.keyType);
		KeyTab.write16(out, key.keyValue.length);
		out.write(key.keyValue);
	}

	public byte[] getEntryBytes() throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		int num_components = principal.nameStrings.length;
		KeyTab.write16(baos, num_components);
		
		KeyTab.writeOctetString(baos, principal.getRealmString());
		
		String[] components = principal.nameStrings;
		for (int i = 0; i < components.length; i++) {
			KeyTab.writeOctetString(baos, components[i]);
		}
		
		KeyTab.write32(baos, principal.getNameType());
		
		KeyTab.write32(baos, (int)(timestamp/1000));
		
		KeyTab.write8(baos, vno8);

		writeEncryptionKey(baos, key);
		
		if (vno!=-1)
			KeyTab.write32(baos, vno);
		
		byte[] bytes = baos.toByteArray();
		return bytes;
	}
	
	public void write(OutputStream out) throws IOException {
		
		byte[] bytes = getEntryBytes();
		
		// write the whole lot, first size, then bytes
		
		KeyTab.write32(out, bytes.length);
		
		out.write(bytes);
	}

	/**
	 * Return as string
	 * 
	 * keysize 54 HTTP/spnego.tst.net@TST.NET ptype 0 (KRB5_NT_UNKNOWN) vno 1
	 * etype 0x3 (DES-CBC-MD5) keylength 8 (0x97137ffdc2a75bfb)
	 * 
	 * @see java.lang.Object#toString()
	 */
	public String toString() {
		StringBuffer sb = new StringBuffer();
		try {
			sb.append("keysize " + getEntryBytes().length);
		} catch (IOException e) {
			e.printStackTrace();
		}
		sb.append(" " + principal);
		sb.append(" ptype " + principal.getNameType());
		sb.append(" (" + principal.getNameTypeName() + ")");
		sb.append(" vno " + vno8);
		sb.append(" "+ key);
		return sb.toString();
	}

}
