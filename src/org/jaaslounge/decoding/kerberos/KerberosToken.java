package org.jaaslounge.decoding.kerberos;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import javax.security.auth.kerberos.KerberosKey;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.jaaslounge.decoding.DecodingException;
import org.jaaslounge.decoding.DecodingUtil;

public class KerberosToken {
	


    private KerberosApRequest apRequest;

    public KerberosToken(byte[] token) throws DecodingException {
        this(token, null);
    }

    public KerberosToken(byte[] token, KerberosKey[] keys) throws DecodingException {

        if(token.length <= 0)
            throw new DecodingException("kerberos.token.empty", null, null);

        try {
            ASN1InputStream stream = new ASN1InputStream(new ByteArrayInputStream(token));
            DERApplicationSpecific derToken = DecodingUtil.as(DERApplicationSpecific.class, stream);
            if(derToken == null || !derToken.isConstructed())
                throw new DecodingException("kerberos.token.malformed", null, null);
            stream.close();

            stream = new ASN1InputStream(new ByteArrayInputStream(derToken.getContents()));
            ASN1ObjectIdentifier kerberosOid = DecodingUtil.as(ASN1ObjectIdentifier.class, stream);
            if(!kerberosOid.getId().equals(KerberosConstants.KERBEROS_OID))
                throw new DecodingException("kerberos.token.invalid", null, null);

            int read = 0;
            int readLow = stream.read() & 0xff;
            int readHigh = stream.read() & 0xff;
            read = (readHigh << 8) + readLow;
            if(read != 0x01)
                throw new DecodingException("kerberos.token.malformed", null, null);

            DERApplicationSpecific krbToken = DecodingUtil.as(DERApplicationSpecific.class, stream);
            if(krbToken == null || !krbToken.isConstructed())
                throw new DecodingException("kerberos.token.malformed", null, null);

            stream.close();

            apRequest = new KerberosApRequest(krbToken.getContents(), keys);
        } catch(IOException e) {
            throw new DecodingException("kerberos.token.malformed", null, e);
        }
    }

    public KerberosTicket getTicket() {
        return apRequest.getTicket();
    }

    public KerberosApRequest getApRequest() {
        return apRequest;
    }

}
