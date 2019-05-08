# JaasLounge fork

## Synopsis

Since JaasLounge seems abandoned we at CBS decided to fork the project since we need the projects feature for our in house development. Since development has stopped in 2010 and Microsoft AD since then has jumped to use AES ciphers in tickets the library needed to be upgrade to handle AES ciphers. The library was also based on an old version of BouncyCastle which uses BouncyCastle API 1.0 and current BouncyCastle uses API 2.0 then the library also needed to be ported to BouncyCastle uses API 2.0.

A feature not implemented in JaasLounge which is crucial to us since we use kerberos as authentication and authorization for our service bus integrations is to be able to fetch secret keys from a keytab file.

The following fork of JaasLounge therefore provides the following:
* Support AES ciphers in Windows AD >= 2008
* Is based on BouncyCastle API 2.0 (BouncyCastle 1.55 used)
* Compiles and run under Java8
* Support secret keys from keytab files to decrypt kerberos tickets

## Installation

```java
package org.jaaslounge.decoding.spnego;

import java.io.File;
import java.io.FileInputStream;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosKey;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.jaaslounge.decoding.kerberos.KerberosAuthData;
import org.jaaslounge.decoding.kerberos.KerberosPacAuthData;
import org.jaaslounge.decoding.kerberos.KerberosToken;
import org.jaaslounge.decoding.pac.PacLogonInfo;
import org.jaaslounge.decoding.pac.PacSid;

import dk.appliedcrypto.spnego.PacUtility;

public class SpnegoTest {

	public SpnegoTest() {
	}

	private static Subject login(String flow) throws LoginException {
		LoginContext lc;
		Subject subject = null;

		lc = new LoginContext(flow);

		lc.login();
		subject = lc.getSubject();

		return subject;
	}

	public static void main(String[] args) throws Exception {

		System.setProperty("java.security.krb5.conf", "./test/spnego-krb5.conf");
		System.setProperty("java.security.auth.login.config", "./test/spnego-jaas.conf");
		System.setProperty("jaaslounge.sso.jaas.config", "./test/spnego-jaas.conf");
		System.setProperty("sun.security.krb5.debug", "true");

		FileInputStream fis = new FileInputStream(new File("./test/security.token"));
		byte[] ba = new byte[65000];
		int c = fis.read(ba);
		fis.close();

		String stoken = new String(ba, 0, c);
		byte[] token = Base64.decode(stoken);

		SpnegoInitToken spnegoToken = new SpnegoInitToken(token);
		String mechanism = spnegoToken.getMechanism();

	
		if (SpnegoConstants.KERBEROS_MECHANISM.equals(mechanism) || SpnegoConstants.LEGACY_KERBEROS_MECHANISM.equals(mechanism)) {
//			Subject subject = login("Server");
//			Set<KerberosKey> creds = subject.getPrivateCredentials(KerberosKey.class);
//			KerberosKey[] keys = creds.toArray(new KerberosKey[creds.size()]);
			byte[] mechanismToken = spnegoToken.getMechanismToken();

			// decrypt the Kerberos ticket encrypted for the server (this is the
			// magic/expensive step!)
			if (Security.getProvider("BC")==null)
				Security.addProvider(new BouncyCastleProvider());
			
			dk.appliedcrypto.spnego.KeyTab keytab = dk.appliedcrypto.spnego.KeyTab.getInstance("./test/some-service-account.keytab");
			KerberosKey[] keys = keytab.getKeys();
			KerberosToken kerberosToken = new KerberosToken(mechanismToken, keys);

			List<KerberosAuthData> authorizations = kerberosToken.getTicket().getEncData().getUserAuthorizations();
			List<String> sids = new ArrayList<String>();
			for (KerberosAuthData authorization : authorizations) {
				// if this isn't the PAC then we can skip past it
				if (!(authorization instanceof KerberosPacAuthData))
					continue;

				// we've got the PAC so crack it open and collect up all the
				// SIDs
				// a SID is a unique identifier in Active Directory that has the
				// form
				// S-1-5-21-185937884-2362668773-3192785854-1139
				// PacUtility.binarySidToStringSid converts the string
				// representation of the
				// byte data into the more readable/familiar form
				PacLogonInfo logonInfo = ((KerberosPacAuthData) authorization).getPac().getLogonInfo();

				if (logonInfo != null) {
					if (logonInfo.getGroupSid() != null) {
						sids.add(logonInfo.getGroupSid().toString());
					}
					if (logonInfo.getGroupSids() != null) {
						for (PacSid pacSid : logonInfo.getGroupSids())
							sids.add(pacSid.toString());
					}
					if (logonInfo.getExtraSids() != null) {
						for (PacSid pacSid : logonInfo.getExtraSids())
							sids.add(pacSid.toString());
					}
					if (logonInfo.getResourceGroupSids() != null) {
						for (PacSid pacSid : logonInfo.getResourceGroupSids())
							sids.add(pacSid.toString());
					}
				}
			}
			System.out.println(PacUtility.binarySidsToStringSids(sids));

		}
	}

}
```
## Contributors

[JaasLounge](http://jaaslounge.sourceforge.net)

CBS: [Michael Rasmussen](mailto:mr.it@cbs.dk)

## License

Copyright jaaslounge.org and [CBS](http://www.cbs.dk)

[LGPLv3](http://www.gnu.org/copyleft/lesser.html)


