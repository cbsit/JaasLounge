package org.jaaslounge.decoding.spnego;

import java.io.File;
import java.io.FileInputStream;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.jaaslounge.AuthenticatedUser;
import org.jaaslounge.decoding.DecodingException;
import org.jaaslounge.decoding.kerberos.KerberosAuthData;
import org.jaaslounge.decoding.kerberos.KerberosPacAuthData;
import org.jaaslounge.decoding.kerberos.KerberosToken;
import org.jaaslounge.decoding.pac.PacLogonInfo;
import org.jaaslounge.decoding.pac.PacSid;
import org.jaaslounge.gss.GSSAuthentication;

public abstract class SpnegoToken {

    // Default max size as 65K
    public static int TOKEN_MAX_SIZE = 66560;

    protected byte[] mechanismToken;
    protected byte[] mechanismList;
    protected String mechanism;

    public static SpnegoToken parse(byte[] token) throws DecodingException {
        SpnegoToken spnegoToken = null;

        if(token.length <= 0)
            throw new DecodingException("spnego.token.empty", null, null);

        switch (token[0]) {
        case (byte)0x60:
            spnegoToken = new SpnegoInitToken(token);
            break;
        case (byte)0xa1:
            spnegoToken = new SpnegoTargToken(token);
            break;
        default:
            spnegoToken = null;
            Object[] args = new Object[]{token[0]};
            throw new DecodingException("spnego.token.invalid", args, null);
        }

        return spnegoToken;
    }

    public byte[] getMechanismToken() {
        return mechanismToken;
    }

    public byte[] getMechanismList() {
        return mechanismList;
    }

    public String getMechanism() {
        return mechanism;
    }
	
	public static void main(String[] args) throws Exception {
		System.setProperty("java.security.krb5.conf", "./test/spnego-krb5.conf");
		System.setProperty("java.security.auth.login.config","./test/spnego-jaas.conf");
		System.setProperty("jaaslounge.sso.jaas.config","./test/spnego-jaas.conf");
		System.setProperty("sun.security.krb5.debug","true");
			
		FileInputStream fis = new FileInputStream(new File("./test/security.token"));
		byte[] ba = new byte[65000];
		int c = fis.read(ba);
		fis.close();
		
		String stoken = new String(ba,0,c);
		byte[] token = Base64.decode(stoken);

		
        try {
            SpnegoToken spnegoToken = SpnegoToken.parse(token);
            String mechanism = spnegoToken.getMechanism();
            byte[] mechanismToken = spnegoToken.getMechanismToken();
            if(SpnegoConstants.KERBEROS_MECHANISM.equals(mechanism)
                    || SpnegoConstants.LEGACY_KERBEROS_MECHANISM.equals(mechanism)) {


                // Authentification du jeton Kerberos
                System.setProperty("javax.security.auth.useSubjectCredsOnly", "false");
                GSSAuthentication authentication = new GSSAuthentication(mechanismToken);
                authentication.getUsername();
                AuthenticatedUser user = new AuthenticatedUser(authentication.getUsername());
                    System.out.println("SPNEGO Authentication succeed with user " + user.getName());
                }

                // D�codage du jeton Kerberos et r�cup�ration des groupes
                Security.addProvider(new BouncyCastleProvider());
                KerberosToken kerberosToken = new KerberosToken(mechanismToken);
                List<KerberosAuthData> userAuthorizations = kerberosToken.getTicket()
                        .getEncData().getUserAuthorizations();
                for(KerberosAuthData kerberosAuthData : userAuthorizations) {
                    if(kerberosAuthData instanceof KerberosPacAuthData) {
                        PacLogonInfo logonInfo = ((KerberosPacAuthData)kerberosAuthData)
                                .getPac().getLogonInfo();

                        List<String> sids = new ArrayList<String>();
                        if(logonInfo.getGroupSid() != null)
                            sids.add(logonInfo.getGroupSid().toString());
                        for(PacSid pacSid : logonInfo.getGroupSids())
                            sids.add(pacSid.toString());
                        for(PacSid pacSid : logonInfo.getExtraSids())
                            sids.add(pacSid.toString());
                        for(PacSid pacSid : logonInfo.getResourceGroupSids())
                            sids.add(pacSid.toString());
                        System.out.println(sids);
                        }
                    }
        } catch(Exception e) {
            e.printStackTrace();
        } 

	}
}
