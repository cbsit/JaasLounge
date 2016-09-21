package org.jaaslounge.decoding;

import java.text.MessageFormat;

public class DecodingException extends Exception {
	private static final long serialVersionUID = 1L;

	private final Throwable cause;

	public DecodingException() {
		this( null, null);
	}

	public DecodingException(String message) {
		this(message, null);
	}

	public DecodingException(Throwable cause) {
		this(null, cause);
	}

	public DecodingException(String key, Object[] args, Throwable cause) {
		this(MessageFormat.format(DecodingMessages.getString(key), args), cause);
	}

	public DecodingException(String message, Throwable cause) {
		super(message);
		this.cause = cause;
	}

	public Throwable getCause() {
		return cause;
	}

}
