/*
 * $Id: DerInputStream.java,v 1.1 2008-06-22 11:28:44 bofriis Exp $
 */
package dk.appliedcrypto.spnego;

import java.io.IOException;
import java.math.BigInteger;
import java.text.ParseException;
import java.util.Date;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERGeneralString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * <p>
 * <small>SPNEGO SSO<br>
 * Copyright(c), Applied Crypto Aps, All rights reserved </small>
 * </p>
 * @author Jens Bo Friis, bofriis@gmail.com
 */
public class DerInputStream {

	private ASN1InputStream is;

	DerInputStream(ASN1InputStream is) {
		this.is = is;
	}

	public DerInputStream(byte[] bytes) throws IOException {
		is = new ASN1InputStream(bytes);
	}

	int available() throws IOException{
		return is.available();
	}

//	public DerValue getDerValue() throws IOException {
//		DERObject obj = is.readObject();
//		return new DerValue(obj);
//	}

	byte[] getBitString() throws IOException {
		DERBitString obj = DERBitString.getInstance(is.readObject());
		return obj.getBytes();
	}

	String getGeneralString() throws IOException {
		DERGeneralString obj = DERGeneralString.getInstance(is.readObject());
		return obj.getString();
	}

	Date getGeneralizedTime() throws IOException {
		ASN1GeneralizedTime obj = DERGeneralizedTime.getInstance(is.readObject());
		try {
			return obj.getDate();
		} catch (ParseException e) {
			e.printStackTrace();
			throw new IOException(e.toString());
		}
	}

	int getInteger() throws IOException {
		ASN1Integer obj = ASN1Integer.getInstance(is.readObject());
		return obj.getValue().intValue();
	}

	byte[] getOctetString() throws IOException {
		ASN1OctetString obj = DEROctetString.getInstance(is.readObject());
		return obj.getOctets();
	}

	ASN1ObjectIdentifier getOID() throws IOException {
		ASN1ObjectIdentifier obj = ASN1ObjectIdentifier.getInstance(is.readObject());
		return obj;
	}

	ASN1Object[] getSequence(int arg) throws IOException {
		ASN1Object obj = is.readObject();
		ASN1Sequence seq = DERSequence.getInstance(obj);
		ASN1Object[] dvs = new ASN1Object[seq.size()];
		Enumeration<ASN1Object> e = ((DERSequence)seq).getObjects();
		for (int i=0; e.hasMoreElements(); i++) {
			Object o = e.nextElement();
			dvs[i] = (ASN1Object)o;
		}
		return dvs;
	}

	BigInteger getEnumerated() throws IOException {
		ASN1Enumerated obj = ASN1Enumerated.getInstance(is.readObject());
		return obj.getValue();
	}

	int getBytes(byte[] bytes) throws IOException {
		return is.read(bytes);
	}
	
	DERApplicationSpecific getApplicationSpecific() throws IOException {
		return (DERApplicationSpecific)is.readObject();
	}
	
	DERTaggedObject getTaggedObject() throws IOException {
		return (DERTaggedObject)is.readObject();
	}
	ASN1Object getObject() throws IOException {
		return (ASN1Object)is.readObject();
	}
	
}
