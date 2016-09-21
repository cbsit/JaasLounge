package org.jaaslounge.decoding.kerberos;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.Key;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.jaaslounge.decoding.DecodingException;
import org.jaaslounge.decoding.DecodingUtil;

public class KerberosRelevantAuthData extends KerberosAuthData {

    private List<KerberosAuthData> authorizations;
    private Properties authdata;

	public Properties getAuthData() {
		return authdata;
	}

    
    public KerberosRelevantAuthData(byte[] token, Key key) throws DecodingException {
    	
//    	System.out.println(HexDump.xdump(token));
//    	dk.appliedcrypto.spnego.Pac pac;
//		try {
//			pac = new dk.appliedcrypto.spnego.Pac(new DerInputStream(token));
//	        authdata = pac.getLogonInfo();
//		} catch (IOException e1) {
//			throw new DecodingException();
//			// TODO Auto-generated catch block
////			e1.printStackTrace();
//		}

    	
        ASN1InputStream stream = new ASN1InputStream(new ByteArrayInputStream(token));
        ASN1Sequence authSequence;
        try {
            authSequence = DecodingUtil.as(ASN1Sequence.class, stream);
            stream.close();
        } catch(IOException e) {
            throw new DecodingException("kerberos.ticket.malformed", null, e);
        }

        authorizations = new ArrayList<KerberosAuthData>();
        Enumeration<?> authElements = authSequence.getObjects();
        while(authElements.hasMoreElements()) {
            ASN1Sequence authElement = DecodingUtil.as(ASN1Sequence.class, authElements);
            ASN1Integer authType = DecodingUtil.as(ASN1Integer.class, DecodingUtil.as(
                    DERTaggedObject.class, authElement, 0));
            DEROctetString authData = DecodingUtil.as(DEROctetString.class, DecodingUtil.as(
                    DERTaggedObject.class, authElement, 1));

            authorizations.addAll(KerberosAuthData.parse(authType.getValue().intValue(), authData
                    .getOctets(), key));
        }
    }

    public List<KerberosAuthData> getAuthorizations() {
        return authorizations;
    }

}
