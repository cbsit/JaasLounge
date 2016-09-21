/*
 * $Id: ConsoleLogger.java,v 1.3 2009-05-12 20:16:46 bofriis Exp $
 */
package dk.appliedcrypto.spnego;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * <p>
 * <small>SPNEGO SSO<br>
 * Copyright(c), Applied Crypto Aps, All rights reserved </small>
 * </p>
 * @author Jens Bo Friis, bofriis@gmail.com
 */
public class ConsoleLogger implements Log {

	private static SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd:hh:mm:ss:SSS");
	public static boolean DEBUG = false;
	public static boolean TRACE = false;
	private String name;

//	private boolean showTimestamps = true;

	/**
	 * @param name
	 */
	public ConsoleLogger(String name) {
		this.name = name;
	}


	private void out(StringBuffer s) {
			System.out.println(s);
	}

//	private void out(String s) {
//			System.out.println(s.toString());
//	}

	/**
	 * @param s
	 */
	public void debug(String s) {
		if (isDebugEnabled()) {
			StringBuffer sb = new StringBuffer();
			prefix(sb, "DEBUG");
			sb.append(s);
			out(sb);
		}
	}

	/**
	 * @return
	 */
	public boolean isDebugEnabled() {
		return DEBUG;
	}

	/**
	 * @param s
	 * @param t
	 */
	public void error(String s, Throwable t) {
		StringWriter sw = new StringWriter();

		StringBuffer sb = new StringBuffer();
		prefix(sb, "ERROR");
		// System.err.println(sb.toString());
		sb.append(s);
		sw.write(sb.toString());
		PrintWriter pw = new PrintWriter(sw);
		// ps.println(sb.toString());
		// PrintWriter pw = new PrintWriter(System.out);
		// pw.print(sb.toString());
		if (t != null) {
			t.printStackTrace(pw);
		}
		pw.close();

		System.err.println(sw.getBuffer());

	}

	/**
	 * @param s
	 */
	public void error(String s) {
		error(s, null);
	}

	/**
	 * @param s
	 */
	public void info(String s) {
		StringBuffer sb = new StringBuffer();
		prefix(sb, "INFO");
		sb.append(s);
		out(sb);
	}

	public void warn(String s) {
		StringBuffer sb = new StringBuffer();
		prefix(sb, "WARN");
		sb.append(s);
		out(sb);
	}

	public void prefix(StringBuffer sb, String type) {
		if (!Boolean.getBoolean("spnego.websphere")) {
			sb.append(sdf.format(new Date(System.currentTimeMillis())));
			sb.append(" [").append(Thread.currentThread().getName()).append("] ");
		}
		sb.append(type).append(" ");
		sb.append(name).append(" - ");
	}

	public void trace(String s) {
		if (TRACE) {
			StringBuffer sb = new StringBuffer();
			prefix(sb, "TRACE");
			sb.append(s);
			out(sb);
		}
	}

	/**
	 * @param showTimestamps
	 */
	public void setTimestamps(boolean showTimestamps) {
		// TODO Auto-generated method stub

	}

	// public static void main(String args) throws Exception {
	// ConsoleLogger log = new ConsoleLogger("test");
	// log.debug("debug");
	// log.warn("warning");
	// log.error("error");
	// log.error("error1", new Throwable());
	//        
	// }

}