package com.canin.crypto.sm;

import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

public class SM3Tool {
    public static byte[] encrypt(byte[] data) {
        SM3Digest digest = new SM3Digest();
        digest.update(data, 0, data.length);
        byte[] result = new byte[digest.getDigestSize()];
        digest.doFinal(result, 0);
        return result;
    }

    public static byte[] encryptByKey(byte[] data, byte[] key) {
        KeyParameter keyParameter = new KeyParameter(key);
        SM3Digest sm3 = new SM3Digest();
        HMac hMac = new HMac(sm3);
        hMac.init(keyParameter);
        hMac.update(data, 0, data.length);
        byte[] result = new byte[hMac.getMacSize()];
        hMac.doFinal(result, 0);
        return result;
    }

}
