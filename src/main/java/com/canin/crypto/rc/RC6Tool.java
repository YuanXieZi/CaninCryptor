package com.canin.crypto.rc;

import com.canin.crypto.util.Paddings;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.RC6Engine;
import org.bouncycastle.crypto.paddings.*;
import org.bouncycastle.crypto.params.KeyParameter;

import java.util.Arrays;

public class RC6Tool {
    //ecb
    private BufferedBlockCipher bufferedBlockCipher;
    private BlockCipherPadding blockCipherPadding;
    private final byte[] key;//The key must have a length of 0-2040
    private final Paddings padding;

    private final boolean isEncryption;

    public RC6Tool(boolean isEncryption, byte[] key, Paddings padding) {
        this.isEncryption = isEncryption;
        this.key = key;
        this.padding = padding;
    }

    private void init() {
        switch (padding) {
            case NONE:
                blockCipherPadding = null;
                break;
            case ZERO:
                blockCipherPadding = new ZeroBytePadding();
                break;
            case PKCS7:
                blockCipherPadding = new PKCS7Padding();
                break;
            case X923:
                blockCipherPadding = new X923Padding();
                break;
            case ISO10126:
                blockCipherPadding = new ISO10126d2Padding();
                break;
            default:
        }
        if (blockCipherPadding != null) {
            bufferedBlockCipher = new PaddedBufferedBlockCipher(new RC6Engine());
        } else {
            bufferedBlockCipher = new BufferedBlockCipher(new RC6Engine());
        }
    }
    public byte[] processingBytes(byte[] data) {
        init();
        bufferedBlockCipher.init(isEncryption, new KeyParameter(key));
        int minSize = bufferedBlockCipher.getOutputSize(data.length);
        byte[] outBuf = new byte[minSize];
        int blocksLength = bufferedBlockCipher.processBytes(data, 0, data.length, outBuf, 0);
        try {
            int lastBlockLength = bufferedBlockCipher.doFinal(outBuf, blocksLength);
            if (outBuf.length == (blocksLength + lastBlockLength)) {
                return outBuf;
            }
            return Arrays.copyOf(outBuf, blocksLength + lastBlockLength);
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException(e);
        }
    }
}
