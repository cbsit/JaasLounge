package dk.appliedcrypto.spnego;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class PBKDF2JCE
{
    public static byte[] deriveKeyHmacSHA1(byte[] salt, long nof_iterations, byte[] pass, int keylen)
    {
        try {
        	if (salt==null)
        		salt = new byte[0];
            // passphrase als input fr key verwenden
            SecretKeySpec keyspec=new SecretKeySpec(pass,"HmacSHA1");
            Mac           mac=Mac.getInstance("HmacSHA1");
            mac.init(keyspec);
            
            // siehe pkcs #5 v2.0
            int    hLen=mac.getMacLength();
            int    dkLen=keylen/8;
            byte[] dk=new byte[dkLen];
            
            int l=((dkLen-1)/hLen)+1;
            int r=dkLen - (l-1)*hLen;
            
      //      System.out.println("deriveKey: hLen="+hLen+"; l="+l+"; r="+r);
            
            byte[] t=new byte[hLen];
            for (long i=0;i<l;i++) {
                Arrays.fill(t,(byte)0);
                
                byte[] u=new byte[salt.length+4];
                System.arraycopy(salt,0, u,0, salt.length);
                u[salt.length+0]=(byte)(((i+1)>>24)&0xFF);
                u[salt.length+1]=(byte)(((i+1)>>16)&0xFF);
                u[salt.length+2]=(byte)(((i+1)>>8)&0xFF);
                u[salt.length+3]=(byte)(((i+1)>>0)&0xFF);
                
                for (int j=0;j<nof_iterations;j++) {
                    u=mac.doFinal(u);
                    for (int k=0;k<t.length;k++) {
                        t[k]^=u[k];
                    }
                }
                
                System.arraycopy(t,0, dk,(int)(i*hLen), ((i!=(l-1))?hLen:r));
            }
            
    //        System.out.print("derived key: ");
//            for (int i=0;i<dk.length;i++) {
//                int x=dk[i]&0xFF;
//                System.out.print(Integer.toString(x,16)+" ");
//            }
      //      System.out.println();
            
            return dk;
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (IllegalStateException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] paddingRFC1423(byte[] input)
    {
        int    len=input.length;
        
        // auf das nchste vielfache von 8 vergrern
        int    newlen=((len>>3)+1)<<3;
        
        // anzahl der angefgten padding-bytes ermitteln
        byte   diff=(byte)(newlen-len);
        
        // output-puffer erzeugen
        byte[] output=new byte[newlen];
        
        // originale daten in output-puffer kopieren
        System.arraycopy(input,0, output,0, len);
        
        // padding besteht aus N bytes mit dem inhalt N
        for (int i=len;i<newlen;i++) {
            output[i]=diff;
        }
    
        return output;
    }

}