package com.wumch.pecar;

import android.util.Log;

import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class Crypto
{
    private String LOG_TAG;

    private Cipher encor;
    private Cipher decor;

    Crypto(String logTag)
    {
        super();
        LOG_TAG = logTag;
    }

    public void encrypt(byte[] in, int len, byte[] out) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException
    {
        System.arraycopy(in, 0, out, 0, len);
//        encor.doFinal(in.array(), 0, len, out.array());
    }

    public void decrypt(byte[] in, int len, byte[] out) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException
    {
        System.arraycopy(in, 0, out, 0, len);
//        decor.doFinal(in.array(), 0, len, out.array());
    }

    public void setEncKeyIv(byte[] key, byte[] iv)
    {
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        try {
            encor = Cipher.getInstance("AES/CFB/NoPadding");
            encor.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        } catch (Exception e) {
            Log.i(LOG_TAG, e.getMessage());
        }
    }

    public void setDecKeyIv(byte[] key, byte[] iv)
    {
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        try {
            decor = Cipher.getInstance("AES/CFB/NoPadding");
            decor.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        } catch (Exception e) {
            Log.i(LOG_TAG, e.getMessage());
        }
    }

    public int genKeyIvList(byte[] chunk) throws NoSuchAlgorithmException
    {
        final int KEY_BITS = 128;
        final int BLOCK_BITS = 128;

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(KEY_BITS);
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        random.setSeed(System.currentTimeMillis());

        int offset = 0;

        SecretKey secretEncKey = keyGen.generateKey();
        byte[] encKey = secretEncKey.getEncoded();
        System.arraycopy(encKey, 0, chunk, offset, encKey.length);
        offset += encKey.length;

        byte[] encIv = new byte[BLOCK_BITS / 8];
        random.nextBytes(encIv);
        System.arraycopy(encIv, 0, chunk, offset, encIv.length);
        offset += encIv.length;

        setEncKeyIv(encKey, encIv);

        SecretKey secretDecKey = keyGen.generateKey();
        byte[] decKey = secretDecKey.getEncoded();
        System.arraycopy(decKey, 0, chunk, offset, decKey.length);
        offset += decKey.length;

        byte[] decIv = new byte[BLOCK_BITS / 8];
        random.nextBytes(decIv);
        System.arraycopy(decIv, 0, chunk, offset, decIv.length);
        offset += decIv.length;

        setDecKeyIv(decKey, decIv);

        return offset;
    }
}
