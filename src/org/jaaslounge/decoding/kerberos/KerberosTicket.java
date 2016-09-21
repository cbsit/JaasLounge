package org.jaaslounge.decoding.kerberos;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.Enumeration;

import javax.security.auth.kerberos.KerberosKey;
import javax.security.auth.login.LoginException;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERGeneralString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.jaaslounge.decoding.DecodingException;
import org.jaaslounge.decoding.DecodingUtil;

public class KerberosTicket {

    private String serverPrincipalName;
    private String serverRealm;
    private KerberosEncData encData;

    public KerberosTicket(byte[] token, byte apOptions, KerberosKey[] keys)
            throws DecodingException {

        if(token.length <= 0)
            throw new DecodingException("kerberos.ticket.empty", null, null);

        ASN1InputStream stream = new ASN1InputStream(new ByteArrayInputStream(token));
        ASN1Sequence sequence;
        try {
            sequence = DecodingUtil.as(ASN1Sequence.class, stream);
            stream.close();
        } catch(IOException e) {
            throw new DecodingException("kerberos.ticket.malformed", null, e);
        }

        Enumeration<?> fields = sequence.getObjects();
        while(fields.hasMoreElements()) {
            DERTaggedObject tagged = DecodingUtil.as(DERTaggedObject.class, fields);
            switch (tagged.getTagNo()) {
            case 0:// Kerberos version
                ASN1Integer tktvno = DecodingUtil.as(ASN1Integer.class, tagged);
                if(!tktvno.getValue().equals(new BigInteger(KerberosConstants.KERBEROS_VERSION))) {
                    Object[] args = new Object[]{KerberosConstants.KERBEROS_VERSION, tktvno};
                    throw new DecodingException("kerberos.version.invalid", args, null);
                }
                break;
            case 1:// Realm
                DERGeneralString derRealm = DecodingUtil.as(DERGeneralString.class, tagged);
                serverRealm = derRealm.getString();
                break;
            case 2:// Principal
                ASN1Sequence principalSequence = DecodingUtil.as(ASN1Sequence.class, tagged);
                ASN1Sequence nameSequence = DecodingUtil.as(ASN1Sequence.class, DecodingUtil.as(
                        DERTaggedObject.class, principalSequence, 1));

                StringBuilder nameBuilder = new StringBuilder();
                Enumeration<?> parts = nameSequence.getObjects();
                while(parts.hasMoreElements()) {
                    Object part = parts.nextElement();
                    DERGeneralString stringPart = DecodingUtil.as(DERGeneralString.class, part);
                    nameBuilder.append(stringPart.getString());
                    if(parts.hasMoreElements())
                        nameBuilder.append('/');
                }
                serverPrincipalName = nameBuilder.toString();
                break;
            case 3:// Encrypted part
                ASN1Sequence encSequence = DecodingUtil.as(ASN1Sequence.class, tagged);
                ASN1Integer encType = DecodingUtil.as(ASN1Integer.class, DecodingUtil.as(
                        DERTaggedObject.class, encSequence, 0));
                DEROctetString encOctets = DecodingUtil.as(DEROctetString.class, DecodingUtil.as(
                        DERTaggedObject.class, encSequence, 2));
                byte[] crypt = encOctets.getOctets();

                if(keys == null) {
                    try {
                        keys = new KerberosCredentials().getKeys();
                    } catch(LoginException e) {
                        throw new DecodingException("kerberos.login.fail", null, e);
                    }
                }

                KerberosKey serverKey = null;
                for(KerberosKey key : keys) {
                    if(key.getKeyType() == encType.getValue().intValue())
                        serverKey = key;
                }

                if(serverKey == null) {
                    Object[] args = new Object[]{encType.getValue().intValue()};
                    throw new DecodingException("kerberos.key.notfound", args, null);
                }

                try {
                    byte[] decrypted = KerberosEncData.decrypt(crypt, serverKey, serverKey.getKeyType());
                    encData = new KerberosEncData(decrypted, serverKey);
                } catch(GeneralSecurityException e) {
                    Object[] args = new Object[]{serverKey.getKeyType()};
                    throw new DecodingException("kerberos.decrypt.fail", args, e);
                }
                break;
            default:
                Object[] args = new Object[]{tagged.getTagNo()};
                throw new DecodingException("kerberos.field.invalid", args, null);
            }
        }

    }

    public String getUserPrincipalName() {
        return encData.getUserPrincipalName();
    }

    public String getUserRealm() {
        return encData.getUserRealm();
    }

    public String getServerPrincipalName() {
        return serverPrincipalName;
    }

    public String getServerRealm() {
        return serverRealm;
    }

    public KerberosEncData getEncData() {
        return encData;
    }

}
