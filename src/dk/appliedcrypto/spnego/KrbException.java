/*
 * $Id: KrbException.java,v 1.1 2008-06-22 11:27:29 bofriis Exp $
 */
package dk.appliedcrypto.spnego;

/**
 * Super class for all authentication exception occurring in the SPNEGO SSO
 * module
 * 
 * <p>
 * <small>SPNEGO SSO<br>
 * Copyright(c), Applied Crypto Aps, All rights reserved </small>
 * </p>
 * @author Jens Bo Friis, bofriis@gmail.com
 */
public class KrbException extends Exception {

	private int krbError = 0;

	/* Integrity check on decrypted field failed */
	public final static int KRB_AP_ERR_BAD_INTEGRITY = 31;

	/* Ticket expired */
	public final static int KRB_AP_ERR_TKT_EXPIRED = 32;

	/* Ticket not yet valid */
	public final static int KRB_AP_ERR_TKT_NYV = 33;

	/* Request is a replay */
	public final static int KRB_AP_ERR_REPEAT = 34;

	/* The ticket isn't for us */
	public final static int KRB_AP_ERR_NOT_US = 35;

	/* Ticket and authenticator don't match */
	public final static int KRB_AP_ERR_BADMATCH = 36;

	/* Clock skew too great */
	public final static int KRB_AP_ERR_SKEW = 37;

	/* Incorrect net address */
	public final static int KRB_AP_ERR_BADADDR = 38;

	/* Protocol version mismatch */
	public final static int KRB_AP_ERR_BADVERSION = 39;

	/* Invalid msg type */
	public final static int KRB_AP_ERR_MSG_TYPE = 40;

	/* Message stream modified */
	public final static int KRB_AP_ERR_MODIFIED = 41;

	/* Message out of order */
	public final static int KRB_AP_ERR_BADORDER = 42;

	/* Specified version of key is not available */
	public final static int KRB_AP_ERR_BADKEYVER = 44;

	/* Service key not available */
	public final static int KRB_AP_ERR_NOKEY = 45;

	/* Mutual authentication failed */
	public final static int KRB_AP_ERR_MUT_FAIL = 46;

	/* Incorrect message direction */
	public final static int KRB_AP_ERR_BADDIRECTION = 47;

	/* Alternative authentication method required */
	public final static int KRB_AP_ERR_METHOD = 48;

	/* Incorrect sequence number in message */
	public final static int KRB_AP_ERR_BADSEQ = 49;

	/* Inappropriate type of checksum in message */
	public final static int KRB_AP_ERR_INAPP_CKSUM = 50;

	/* Policy rejects transited path */
	public final static int KRB_AP_PATH_NOT_ACCEPTED = 51;

	/* General error */
	public final static int KRB_GENERAL_ERROR = 1001;

	
	/**
	 * 
	 */
	private static final long serialVersionUID = -4167071317431160434L;

	/**
	 * 
	 */
	public KrbException(int krbError) {
		super();
		this.krbError = krbError;
	}

	/**
	 * @param message
	 */
	public KrbException(int krbError, String message) {
		super(message);
		this.krbError = krbError;
	}

	/**
	 * @param cause
	 */
	public KrbException(int krbError, Throwable cause) {
		super(cause);
		this.krbError = krbError;
	}

	/**
	 * @param message
	 * @param cause
	 */
	public KrbException(int krbError, String message, Throwable cause) {
		super(message, cause);
		this.krbError = krbError;
	}

	public int getKrbError() {
		return krbError;
	}
}
