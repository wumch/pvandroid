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

final class Crypto
{
    private String LOG_TAG;

    private Cipher encor;
    private Cipher decor;

    Crypto(String logTag)
    {
        super();
        LOG_TAG = logTag;
    }

    public final void encrypt(ByteBuffer in, ByteBuffer out) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException
    {
        out.position(out.position() + encor.update(in.array(), 0, in.limit(), out.array(), out.position()));
    }

    public final void decrypt(ByteBuffer in, ByteBuffer out) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException
    {
        out.position(out.position() + decor.update(in.array(), 0, in.limit(), out.array(), out.position()));
    }

    public byte[] encrypt(byte[] data) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException
    {
        return encor.update(data);
    }

    public byte[] decrypt(byte[] data) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException
    {
        return decor.update(data);
    }

    public final void setEncKeyIv(byte[] key, byte[] iv)
    {
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        try {
            encor = Cipher.getInstance("AES/CFB/NoPadding");
            encor.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        } catch (Exception e) {
            Log.i(LOG_TAG, e.getMessage());
        }
    }

    public final void setDecKeyIv(byte[] key, byte[] iv)
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

    public final int genKeyIvList(byte[] chunk) throws NoSuchAlgorithmException
    {
        final int KEY_BITS = 128;
        final int BLOCK_BITS = 128;

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(KEY_BITS);
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        random.setSeed(System.currentTimeMillis()^ Thread.currentThread().getId() ^ (hashCode() * keyGen.hashCode()));

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
