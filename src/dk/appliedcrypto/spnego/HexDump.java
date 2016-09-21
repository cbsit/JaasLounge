package dk.appliedcrypto.spnego;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.util.StringTokenizer;

/**
 * Hexdumper
 * 
 * <p>
 * <small>SPNEGO SSO<br>
 * Copyright(c), Applied Crypto Aps, All rights reserved </small>
 * </p>
 * @author Jens Bo Friis, bofriis@gmail.com
 */
public final class HexDump {

	static char[] hexstr = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

	/**
	 * Convert byte value to hexadecimal string representation (for trace dumps)
	 * 
	 * @return java.lang.String
	 * @param value
	 *            byte
	 * @param digits
	 *            int
	 */
	public static String tohex(byte value, int digits) {
		return tohex((int) value, digits);
	}

	/**
	 * Convert byte value to hexadecimal string representation (for trace dumps)
	 * 
	 * @return java.lang.String
	 * @param value
	 *            int
	 * @param digits
	 *            int
	 */
	public static String tohex(int value, int digits) {
		char[] ret = new char[digits];
		int n;
		byte a;

		for (n = 0; n < digits; n++) {
			a = (byte) (value & 0x0F);
			value >>= 4;

			ret[digits - n - 1] = hexstr[a];
		}

		return String.valueOf(ret);
	}

	public static String hex(byte[] bytes) {
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < bytes.length; i++)
			sb.append(tohex(bytes[i], 2));
		return "0x" + sb.toString().toLowerCase();
	}

	public static String xdump(byte[] bytes) {
		if (bytes == null)
			bytes = new byte[0];
		return xdump(bytes, 0, bytes.length);
	}

	/**
	 * Dumps data block in hexadecimal representation (part of trace action)
	 * 
	 * @param bytes
	 *            byte[]
	 */
	public static String xdump(byte[] bytes, int offset, int len) {
		if (bytes == null)
			bytes = new byte[0];
		int ofs = offset, count = 0;
		int n;
		StringBuffer sb = new StringBuffer(80);
		StringBuffer outstr = new StringBuffer(5 * len);

		while (ofs < len) {
			count = (len - ofs) < 16 ? (len - ofs) : 16;

			sb.setLength(0);

			sb.append(tohex(ofs, 4));
			sb.append(": ");

			// First, the hex bytes
			for (n = 0; n < count; n++) {
				if (n == 8)
					sb.append("- ");
				sb.append(tohex((int) bytes[ofs + n], 2));
				sb.append(' ');
			}

			// Then fill up with spaces
			for (n = count; n < 16; n++)
				sb.append("   ");

			if (count < 9) // Add the '- ' if we need it.
				sb.append("  ");

			// Seperate hex bytes from ascii chars
			sb.append(" ");

			// And last, the ascii characters
			for (n = 0; n < count; n++) {
				char b = (char) bytes[ofs + n];

				if (b >= (char) 32 && (char) b <= 127)
					sb.append(b);
				else
					sb.append('.');
			}

			sb.append("\r\n");
			outstr.append(sb.toString());
			// log(sb.toString());
			ofs += count;
		}

		return outstr.toString();
	}

	public static byte[] toBytes(String hexdump) throws IOException {
		return toBytes(hexdump, 0);
	}

	public static byte[] toBytesOld(String hexdump, int startidx) throws IOException {
		
		StringReader sr = new StringReader(hexdump);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		BufferedReader br = new BufferedReader(sr);
		String line = null;
		while ((line = br.readLine()) != null) {
			/* "0bc0: 30 9f 5a 2f 79 f6 ef 04 - 5a f5 bf 19 18 29 ca  0.Z.y...Z...... */
			/* "0000: 01 00 6e 82 0b c9 30 82 - 0b c5 a0 03 02 01 05 a1  ..n...0......... */
			/* "0000: 01 00 6e 82 0b c9 30 82 - 0b c5 a0 03 02 01 05 a1" */
			
			/* "0000  AC 88 7C A4 D5 1E A7 28 47 2E 75 86 9D 54 64 57 ..|....(G.u..TdW */
			line = line.trim();
			if (line.equals(""))
				continue;
			line = line.substring(startidx);
//			String saddr = line.substring(0, 4);
			int idx = 0;
			if (line.indexOf(": ")!=-1) {
				idx =  line.indexOf(" ") + 2;
			} else {
				idx = line.indexOf(": ") + 2;
			}
			int idx1 = line.indexOf("  ", idx);
			if (idx1 == -1)
				idx1 = line.length();
			String data = line.substring(idx, idx1);
			StringTokenizer st = new StringTokenizer(data, " -");
			for (int i = 0; i < 16; i++) {
				if (st.hasMoreTokens()) {
					String aByte = st.nextToken();
					baos.write(Integer.parseInt(aByte, 16));
					// System.out.println(i+" "+aByte);
				}
			}
		}
		return baos.toByteArray();
	}

	public static byte[] toBytes(String hexdump, int startidx) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		StringTokenizer st1 = new StringTokenizer(hexdump,"\r\n");
		while (st1.hasMoreTokens()) {
			String line = st1.nextToken();
			line = line.substring(startidx);
//			String saddr = line.substring(0, 4);
			int idx = 0;
			if (line.indexOf(": ")==-1) {
				idx =  line.indexOf("  ") + 2;
			} else {
				idx = line.indexOf(": ") + 2;
			}
			int idx1 = line.indexOf("  ", idx);
			if (idx1 == -1)
				idx1 = line.length();
			String data = line.substring(idx, idx1);
			StringTokenizer st = new StringTokenizer(data, " -");
			for (int i = 0; i < 16; i++) {
				if (st.hasMoreTokens()) {
					String aByte = st.nextToken();
					baos.write(Integer.parseInt(aByte, 16));
					// System.out.println(i+" "+aByte);
				}
			}
		}
		return baos.toByteArray();
	}

	
	public static byte[] toTcpDumpBytes(File file) throws IOException {

		FileInputStream fis = null;
		try {
			fis = new FileInputStream(file);
			StringBuffer sb = new StringBuffer();
			byte[] bytes = new byte[4096];
			while (fis.available() > 0) {
				int i = fis.read(bytes);
				sb.append(new String(bytes, 0, i));
			}
			return toTcpDumpBytes(sb.toString());
		} finally {
			if (fis!=null)
				fis.close();
		}
	}

	public static byte[] toTcpDumpBytes(String hexdump) throws IOException {
		StringReader sr = new StringReader(hexdump);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		BufferedReader br = new BufferedReader(sr);
		String line = null;
		while ((line = br.readLine()) != null) {
			// "30 9f 5a 2f 79 f6 ef 04 		0.Z.y...Z......"
			line = line.trim();
			if (line.equals(""))
				continue;
			int idx1 = line.indexOf("  ");
			if (idx1 == -1)
				idx1 = line.length();
			String data = line.substring(0, idx1);
			StringTokenizer st = new StringTokenizer(data, " ");
			for (int i = 0; i < 8; i++) {
				if (st.hasMoreTokens()) {
					String aByte = st.nextToken();
					baos.write(Integer.parseInt(aByte, 16));
					// System.out.println(i+" "+aByte);
				}
			}
		}
		return baos.toByteArray();
	}

	public static byte[] toBytes(File file) throws IOException {
		return toBytes(file, 0);
	}

	public static byte[] toBytes(File file, int startidx) throws IOException {
		FileInputStream fis = null;
		try {
			fis = new FileInputStream(file);
			StringBuffer sb = new StringBuffer();
			byte[] bytes = new byte[4096];
			while (fis.available() > 0) {
				int i = fis.read(bytes);
				sb.append(new String(bytes, 0, i));
			}
			return toBytes(sb.toString(), startidx);
		} finally {
			if (fis!=null)
				fis.close();
		}
	}

	public static void main(String[] args) throws Exception {
		String s = "10 01 05 FE 00 00 01 00         ........        \r\nF6 05 00 00 02 00 09 72         .......\r\nFF 7F 00 00 00 00 00 00         ........";
		byte[] bytes = toTcpDumpBytes(s);
		System.out.println(HexDump.xdump(bytes));
	}

}