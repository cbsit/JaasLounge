/*
 * $Id: Realm.java,v 1.2 2008-08-05 07:31:29 bofriis Exp $
 */
package dk.appliedcrypto.spnego;

import java.io.IOException;

/**
 * Implements the Realm type. <xmp>Realm ::= GeneralString </xmp>
 * <p>
 * <small>SPNEGO SSO<br>
 * Copyright(c), Applied Crypto Aps, All rights reserved </small>
 * </p>
 * @author Jens Bo Friis, bofriis@gmail.com
 */
public final class Realm {

	String realm = null;

	public Realm(String realm) {
		this.realm = realm;
	}
	
    Realm(byte[] bytes) throws IOException {
        this(new DerInputStream(bytes));
    }
    
	Realm(DerInputStream dis) throws IOException {
		realm = dis.getGeneralString();
	}

//	Realm(DerValue dv) throws IOException {
//		this(dv.getData());
//	}

	byte[] getEncoded() throws IOException {
		if (realm == null)
			throw new IOException("realm==null");
		return new DerOutputStream().putGeneralString(realm).toByteArray();
	}
    
    public String toString() {
        return realm;
    }
}