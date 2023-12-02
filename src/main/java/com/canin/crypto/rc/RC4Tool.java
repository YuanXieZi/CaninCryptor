package com.canin.crypto.rc;

import org.bouncycastle.crypto.engines.RC4Engine;
import org.bouncycastle.crypto.params.KeyParameter;

public class RC4Tool {
    private final byte[] key;

    private final boolean isEncryption;

    public RC4Tool(boolean isEncryption, byte[] key) {
        this.key = key;
        this.isEncryption = isEncryption;
    }

    public byte[] processingBytes(byte[] data, int offset, int length) {
        RC4Engine rc4Engine = new RC4Engine();
        KeyParameter keyParameter = new KeyParameter(key);
        rc4Engine.init(isEncryption, keyParameter);
        byte[] out = new byte[length];
        rc4Engine.processBytes(data, offset, length, out, 0);
        return out;
    }

    public byte[] processingBytes(byte[] data) {
        return processingBytes(data, 0, data.length);
    }
}
