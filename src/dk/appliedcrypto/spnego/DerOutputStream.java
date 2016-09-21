/*
 * $Id: DerOutputStream.java,v 1.1 2008-06-22 11:28:45 bofriis Exp $
 */
package dk.appliedcrypto.spnego;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERGeneralString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;

/**
  * <p>
 * <small>SPNEGO SSO<br>
 * Copyright(c), Applied Crypto Aps, All rights reserved </small>
 * </p>
 * @author Jens Bo Friis, bofriis@gmail.com
 */
public class DerOutputStream {

	private ASN1OutputStream aos;

	private ByteArrayOutputStream baos;

	ASN1OutputStream getObject() {
		return aos;
	}

	DerOutputStream() throws IOException {
		baos = new ByteArrayOutputStream();
		aos = new ASN1OutputStream(baos);
	}

	byte[] toByteArray() {
		return baos.toByteArray();
	}

	DerOutputStream putDERObject(ASN1Object dv) throws IOException {
		aos.writeObject(dv);
		return this;
	}

	DerOutputStream putInteger(int integer) throws IOException {
		aos.writeObject(new ASN1Integer(integer));
		return this;
	}

//	DerOutputStream write(byte[] bytes) throws IOException {
//		aos.write(bytes);
//		return this;
//	}

//	DerOutputStream write(byte tag, byte[] bytes) throws IOException {
//		aos.writeObject(new ASN1UnknownTag(tag, bytes));
//		return this;
//	}

	DerOutputStream putBitString(byte[] bytes) throws IOException {
		aos.writeObject(new DERBitString(bytes));
		return this;
	}

	DerOutputStream putOctetString(byte[] bytes) throws IOException {
		aos.writeObject(new DEROctetString(bytes));
		return this;
	}

//	DerOutputStream write(byte tag, DerOutputStream dos) throws IOException {
//		aos.writeObject(new DERUnknownTag(tag, dos.toByteArray()));
//		return this;
//	}

//	DerOutputStream write(int tag) throws IOException {
//		aos.write(tag);
//		return this;
//	}

//	DerOutputStream write(byte[] bytes, int index, int len) throws IOException {
//		aos.write(bytes, index, len);
//		return this;
//	}

//	DerOutputStream putLength(int len) throws IOException {
//		if (len < 128) {
//			write((byte) len);
//
//		} else if (len < (1 << 8)) {
//			write((byte) 0x081);
//			write((byte) len);
//
//		} else if (len < (1 << 16)) {
//			write((byte) 0x082);
//			write((byte) (len >> 8));
//			write((byte) len);
//
//		} else if (len < (1 << 24)) {
//			write((byte) 0x083);
//			write((byte) (len >> 16));
//			write((byte) (len >> 8));
//			write((byte) len);
//
//		} else {
//			write((byte) 0x084);
//			write((byte) (len >> 24));
//			write((byte) (len >> 16));
//			write((byte) (len >> 8));
//			write((byte) len);
//		}
//		return this;
//	}

	DerOutputStream putOID(ASN1ObjectIdentifier oid) throws IOException {
		aos.writeObject(oid);
		return this;
	}

	DerOutputStream putGeneralString(String s) throws IOException {
		aos.writeObject(new DERGeneralString(s));
		return this;
	}

	DerOutputStream putGeneralizedTime(Date date) throws IOException {
		aos.writeObject(new DERGeneralizedTime(date));
		return this;
	}

	DerOutputStream putSequence(ASN1Object[] objs) throws IOException {
		DERSequence seq = new DERSequence(objs);
		aos.writeObject(seq);
		return this;
	}
}