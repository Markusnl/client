package client;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import static javax.xml.bind.DatatypeConverter.printHexBinary;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.ChaChaEngine;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

public class Crypto {
   
    public byte[] getMac(byte[] input){
        byte mac[] = new byte[32];
        System.arraycopy(input, 0, mac, 0, 32);
        return mac;
    }
    
    public byte[] getNonce(byte[] input){
        byte nonce[] = new byte[8];
        System.arraycopy(input, 32, nonce, 0, 8);
        return nonce;
    }
    
     public byte[] getData(byte[] input){
        byte data[] = new byte[input.length-40];
        System.arraycopy(input, 40, data, 0, data.length);
        return data;
    }

    public byte[] prependMac(byte[] mac, byte[] data) {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            outputStream.write(mac);
            outputStream.write(data);
        } catch (IOException ex) {
            Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        }     
       return outputStream.toByteArray();
    };
    
    public byte[] prependNonce(byte[] nonce, byte[] data) {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            outputStream.write(nonce);
            outputStream.write(data);
        } catch (IOException ex) {
            Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        }     
       return outputStream.toByteArray();
    };
    
    
    public boolean verifyMac(byte[] key, byte[] data, byte[] mac, boolean received) {
        Digest digest = new SHA256Digest();
        HMac hmac = new HMac(digest);
        hmac.init(new KeyParameter(key));
        
        //Mac still prepended to message, remove it first to calculate validity
        if (received){
            data = removeMac(data);
        }
        
        hmac.update(data, 0, data.length);
        byte[] resBuf = new byte[digest.getDigestSize()];
        hmac.doFinal(resBuf, 0);

        /*System.out.println("computed mac: " + printHexBinary(resBuf));
        System.out.println("given mac: " + printHexBinary(mac));*/

        return Arrays.equals(resBuf, mac);
    }

    public byte[] generateMac(byte[] key, byte[] data) {
        Digest digest = new SHA256Digest();
        HMac hmac = new HMac(digest);
        hmac.init(new KeyParameter(key));
        hmac.update(data, 0, data.length);
        byte[] resBuf = new byte[digest.getDigestSize()];
        hmac.doFinal(resBuf, 0);

        return resBuf;
    }

    public byte[] ChaCha(byte[] key, byte[] nonce, byte[] in) {
        //create chacha engine with key and IV
        CipherParameters cp = new KeyParameter(key);
        ParametersWithIV params = new ParametersWithIV(cp, nonce);
        StreamCipher engine = new ChaChaEngine();
        engine.init(true, params);

        //encrypt/decrypt and return output
        byte out[] = new byte[in.length];
        engine.processBytes(in, 0, in.length, out, 0);
        return out;
    }

    public byte[] createRandom(int length) {
        //create secure random key and nonce
        byte random[] = new byte[length];
        SecureRandom sr = null;
        try {
            sr = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        }
        sr.nextBytes(random);
        return random;
    }
    
    public byte[] createKey(){
        return createRandom(32);
    }
    
    public byte[] reKey(){
        //additional reKeying operations
        return createKey();
    }
    
    public byte[] createNonce(){
        return createRandom(8);
    }

    private byte[] removeMac(byte[] input) {
        byte data[] = new byte[input.length-32];
        System.arraycopy(input, 32, data, 0, data.length);
        return data;
    }
    

}
