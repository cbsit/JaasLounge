/*
 * $Id: RC4.java,v 1.1 2008-06-22 11:27:28 bofriis Exp $
 */
package dk.appliedcrypto.spnego;

/**
 *  * <p>
 * <small>SPNEGO SSO<br>
 * Copyright(c), Applied Crypto Aps, All rights reserved </small>
 * </p>
 * @author Jens Bo Friis, bofriis@gmail.com
 *
 */
public class RC4 {

    int    x;
    int    y;
    byte[] state = new byte[256];

    final int arcfour_byte() {
      int x;
      int y;
      int sx, sy;

      x = (this.x + 1) & 0xff;
      sx = (int)state[x];
      y = (sx + this.y) & 0xff;
      sy = (int)state[y];
      this.x = x;
      this.y = y;
      state[y] = (byte)(sx & 0xff);
      state[x] = (byte)(sy & 0xff);
      return (int)state[((sx + sy) & 0xff)];
    }

    public synchronized byte[] encrypt(byte[] in) {
      byte[] out = new byte[in.length];
      for(int i = 0; i < in.length; i++)
        out[i] = (byte)(((int)in[i] ^ arcfour_byte()) & 0xff);
      return out;
    }

    /**
     * decrypt = encrypt(encrypt).
     * @param in
     * @return
     */
    public byte[] decrypt(byte[] in) {
      return encrypt(in);
    }

    public void setKey(byte[] key) {
      int t, u;
      int keyindex;
      int stateindex;
      int counter;
      
      for(counter = 0; counter < 256; counter++)
        state[counter] = (byte)counter;
      keyindex = 0;
      stateindex = 0;
      for(counter = 0; counter < 256; counter++) {
        t = (int)state[counter];
        stateindex = (stateindex + key[keyindex] + t) & 0xff;
        u = (int)state[stateindex];
        state[stateindex] = (byte)(t & 0xff);
        state[counter] = (byte)(u & 0xff);
        if(++keyindex >= key.length)
    keyindex = 0;
      }
    }
}
