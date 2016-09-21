/*
 * $Id: Log.java,v 1.2 2008-07-29 19:36:46 bofriis Exp $
 */
package dk.appliedcrypto.spnego;

/**
 * 
 * <p>
 * <small>SPNEGO SSO<br>
 * Copyright(c), Applied Crypto Aps, All rights reserved </small>
 * </p>
 * @author Jens Bo Friis, bofriis@gmail.com
 */
public interface Log {
	public void debug(String s);

	public boolean isDebugEnabled();

	public void error(String s, Throwable t);

	public void error(String s);

	public void info(String s);

	public void trace(String s);

	public void warn(String s);

	public void setTimestamps(boolean showTimestamps);
}
