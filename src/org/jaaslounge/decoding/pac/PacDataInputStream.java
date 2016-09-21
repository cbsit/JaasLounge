package org.jaaslounge.decoding.pac;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Date;

import org.jaaslounge.decoding.DecodingException;

public class PacDataInputStream {

    private DataInputStream dis;
    private int size;

    public PacDataInputStream(InputStream in) throws IOException {
        dis = new DataInputStream(in);
        size = in.available();
    }

    public void align(int mask) throws IOException {
        int position = size - dis.available();
        int shift = position & mask - 1;
        if(mask != 0 && shift != 0)
            dis.skip(mask - shift);
    }

    public int available() throws IOException {
        return dis.available();
    }

    public void readFully(byte[] b) throws IOException {
        dis.readFully(b);
    }

    public void readFully(byte[] b, int off, int len) throws IOException {
        dis.readFully(b, off, len);
    }

    public char readChar() throws IOException {
        align(2);
        return dis.readChar();
    }

    public byte readByte() throws IOException {
        return dis.readByte();
    }

    public short readShort() throws IOException {
        align(2);
        return Short.reverseBytes((short)dis.readShort());
    }

    public int readInt() throws IOException {
        align(4);
        return Integer.reverseBytes(dis.readInt());
    }

    public long readLong() throws IOException {
        align(8);
        return Long.reverseBytes(dis.readLong());
    }

    public int readUnsignedByte() throws IOException {
        return ((int)readByte()) & 0xff;
    }

    public long readUnsignedInt() throws IOException {
        return ((long)readInt()) & 0xffffffffL;
    }

    public int readUnsignedShort() throws IOException {
        return ((int)readShort()) & 0xffff;
    }

    public Date readFiletime() throws IOException {
        Date date = null;

        long last = readUnsignedInt();
        long first = readUnsignedInt();
        if(first != 0x7fffffffL && last != 0xffffffffL) {
            BigInteger lastBigInt = BigInteger.valueOf(last);
            BigInteger firstBigInt = BigInteger.valueOf(first);
            BigInteger completeBigInt = lastBigInt.add(firstBigInt.shiftLeft(32));
            completeBigInt = completeBigInt.divide(BigInteger.valueOf(10000L));
            completeBigInt = completeBigInt.add(BigInteger.valueOf(PacConstants.FILETIME_BASE));
            date = new Date(completeBigInt.longValue());
        }

        return date;
    }

    public PacUnicodeString readUnicodeString() throws IOException, DecodingException {
        short length = readShort();
        short maxLength = readShort();
        int pointer = readInt();

        if(maxLength < length) {
            throw new DecodingException("pac.string.malformed.size", null, null);
        }

        return new PacUnicodeString(length, maxLength, pointer);
    }

    public String readString() throws IOException, DecodingException {
        int totalChars = readInt();
        int unusedChars = readInt();
        int usedChars = readInt();

        if(unusedChars > totalChars || usedChars > totalChars - unusedChars)
            throw new DecodingException("pac.string.malformed.size", null, null);

        dis.skip(unusedChars * 2);
        char[] chars = new char[usedChars];
        for(int l = 0; l < usedChars; l++)
            chars[l] = (char)readShort();

        return new String(chars);
    }

    public PacSid readId() throws IOException, DecodingException {
        byte[] bytes = new byte[4];
        readFully(bytes);

        return PacSid.createFromSubs(bytes);
    }

    public PacSid readSid() throws IOException, DecodingException {
        int sidSize = readInt();

        byte[] bytes = new byte[8 + sidSize * 4];
        readFully(bytes);

        return new PacSid(bytes);
    }

    public int skipBytes(int n) throws IOException {
        return dis.skipBytes(n);
    }

}