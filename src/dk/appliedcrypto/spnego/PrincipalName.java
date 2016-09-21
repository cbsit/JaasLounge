/*
 * $Id: PrincipalName.java,v 1.7 2008-12-28 23:54:24 bofriis Exp $
 */
package dk.appliedcrypto.spnego;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Vector;

/**
 * <p>
 * PrincipalName ::= SEQUENCE {<br>
 * name-type[0] INTEGER, <br>
 * name-string[1] SEQUENCE OF GeneralString <br>}<br>
 * <p>
 * <small>SPNEGO SSO<br>
 * Copyright(c), Applied Crypto Aps, All rights reserved </small>
 * </p>
 * @author Jens Bo Friis, bofriis@gmail.com
 */
public final class PrincipalName {
	private static Log LOG = LogFactory.getLog("PrincipalName");

	public static final int KRB_NT_UNKNOWN = 0;

	public static final int KRB_NT_PRINCIPAL = 1;

	public static final int KRB_NT_SRV_INST = 2;

	public static final int KRB_NT_SRV_HST = 3;

	public static final int KRB_NT_SRV_XHST = 4;

	public static final int KRB_NT_UID = 5;

	public static final String[] nameTypeNames = new String[] { "KRB_NT_UNKNOWN", "KRB_NT_PRINCIPAL", "KRB_NT_SRV_INST", "KRB_NT_SRV_HST", "KRB_NT_SRV_XHST", "KRB_NT_UID" };

	public static final String TGS_DEFAULT_SRV_NAME = "krbtgt";

	public static final int TGS_DEFAULT_NT = KRB_NT_SRV_INST;

	public static final char NAME_COMPONENT_SEPARATOR = '/';

	public static final char NAME_REALM_SEPARATOR = '@';

	public static final char REALM_COMPONENT_SEPARATOR = '.';

	public static final String NAME_COMPONENT_SEPARATOR_STR = "/";

	public static final String NAME_REALM_SEPARATOR_STR = "@";

	public static final String REALM_COMPONENT_SEPARATOR_STR = ".";

	BigInteger nameType = BigInteger.ZERO;

	String[] nameStrings = null;

	byte[] baPrincipalName = null;

	private Realm nameRealm; // optional; a null realm means use default

//	PrincipalName(byte[] bytes) throws IOException {
//		this(new DerInputStream(bytes));
//	}

	public int getNameType() {
		return nameType.intValue();
	}

	public String getNameTypeName() {
		return nameTypeNames[nameType.intValue()];
	}

	public PrincipalName(String[] nameStrings, int nameType) throws IOException {
		this.nameStrings = nameStrings;
		this.nameType = BigInteger.valueOf(nameType);
	}

	public PrincipalName(String name) throws IOException {
		this(name, KRB_NT_PRINCIPAL);
	}


	
	public PrincipalName(String name, int nameType) throws IOException {

		String[] nameStrings = parseName(name);
		this.nameStrings = nameStrings;
		this.nameType = BigInteger.valueOf(nameType);

		if (name.indexOf('@') != -1) {
			Realm realm = new Realm(name.substring(name.indexOf('@') + 1));
			name = name.substring(0, name.indexOf('@'));
			setRealm(realm);
		}
	}

	/**
	 * Realm ::= GeneralString PrincipalName ::= SEQUENCE { name-type[0]
	 * INTEGER, name-string[1] SEQUENCE OF GeneralString }
	 * 
	 * @param dis
	 * @throws IOException
	 */
//	PrincipalName(DerInputStream dis) throws IOException {
//		DerValue dv = dis.getDerValue();
//		baPrincipalName = dv.encoded();
//		dis = new DerInputStream(baPrincipalName);
//		DERObject[] derObjs = dis.getSequence(2);
//		for (int i = 0; i < derObjs.length; i++) {
//			DERObject derobj = derObjs[i];
//			switch (((DERTaggedObject) derobj).getTagNo()) {
//			case 0x0:
//				DERInteger integer = (DERInteger) ((DERTaggedObject) derobj).getObject();
//				nameType = integer.getValue();
//				break;
//			case 0x1:
//				DERSequence seq = (DERSequence) ((DERTaggedObject) derobj).getObject();
//				nameStrings = new String[seq.size()];
//				for (int j = 0; j < nameStrings.length; j++) {
//					nameStrings[j] = ((DERGeneralString) seq.getObjectAt(j)).getString();
//				}
//				break;
//			}
//
//		}
		// System.out.println("REMOVE ME: " +toString());
//	}

	byte[] getEncoded() throws IOException {
		if (LOG.isDebugEnabled())
			LOG.debug("PrincipalName***\r\n" + HexDump.xdump(baPrincipalName));
		return baPrincipalName;
	}

	public String toString() {
		StringBuffer str = new StringBuffer();
		for (int i = 0; i < nameStrings.length; i++) {
			if (i > 0)
				str.append(NAME_COMPONENT_SEPARATOR);
			str.append(nameStrings[i]);
		}
		if (nameRealm != null) {
			str.append(NAME_REALM_SEPARATOR);
			str.append(nameRealm.toString());
		}

		return str.toString();
	}

	private static String[] parseName(String name) {

		Vector<String> tempStrings = new Vector<String>();

		String temp = name;
		int i = 0;
		int componentStart = 0;
		String component;

		while (i < temp.length()) {
			if (temp.charAt(i) == NAME_COMPONENT_SEPARATOR) {
				/*
				 * If this separator is escaped then don't treat it as a
				 * separator
				 */
				if (i > 0 && temp.charAt(i - 1) == '\\') {
					temp = temp.substring(0, i - 1) + temp.substring(i, temp.length());
					continue;
				} else {
					if (componentStart < i) {
						component = temp.substring(componentStart, i);
						tempStrings.addElement(component);
					}
					componentStart = i + 1;
				}
			} else if (temp.charAt(i) == NAME_REALM_SEPARATOR) {
				/*
				 * If this separator is escaped then don't treat it as a
				 * separator
				 */
				if (i > 0 && temp.charAt(i - 1) == '\\') {
					temp = temp.substring(0, i - 1) + temp.substring(i, temp.length());
					continue;
				} else {
					if (componentStart < i) {
						component = temp.substring(componentStart, i);
						tempStrings.addElement(component);
					}
					componentStart = i + 1;
					break;
				}
			}
			i++;
		}

		if (i == temp.length())
			if (componentStart < i) {
				component = temp.substring(componentStart, i);
				tempStrings.addElement(component);
			}

		String[] result = new String[tempStrings.size()];
		tempStrings.copyInto(result);
		return result;
	}

	public String getRealmString() {
		if (nameRealm != null)
			return nameRealm.toString();
		return null;
	}

	public Realm getRealm() {
		return nameRealm;
	}

	public void setRealm(Realm new_nameRealm) {
		nameRealm = new_nameRealm;
	}

	public byte[] getSalt() {
		StringBuffer sb = new StringBuffer();
		if (getRealmString()!=null)
			sb.append(getRealmString());
		for (int i=0; i<nameStrings.length; i++)
			sb.append(nameStrings[i]);
		return sb.toString().getBytes();
	}

	public boolean equals(Object obj) {
		if (!(obj instanceof PrincipalName))
			return false;
		return toString().equals(obj.toString());
	}
	
	public static void main(String[] args) throws IOException {
		PrincipalName princ = new PrincipalName("HTTP/webserver.test2008.net@TEST2008.NET", PrincipalName.KRB_NT_PRINCIPAL);
		System.out.println(HexDump.xdump(princ.getSalt()));
	}
}