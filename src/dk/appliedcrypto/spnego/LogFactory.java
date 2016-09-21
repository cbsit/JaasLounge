/*
 * $Id: LogFactory.java,v 1.3 2009-05-12 21:21:09 bofriis Exp $
 */
package dk.appliedcrypto.spnego;

/**
 * <p>
 * <small>SPNEGO SSO<br>
 * Copyright(c), Applied Crypto Aps, All rights reserved </small>
 * </p>
 * @author Jens Bo Friis, bofriis@gmail.com
 */
public class LogFactory {

	
	public static Log getLog(String name) {
		return new ConsoleLogger(name);
	}
}
