package com.canin.crypto;

import org.bouncycastle.util.encoders.Hex;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHA1Tool {
    public static String encrypt(byte[] data) {
        MessageDigest sha ;
        try {
            sha = MessageDigest.getInstance("SHA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        sha.reset();
        sha.update(data);
        return Hex.toHexString(sha.digest());
    }

}
