package com.canin.crypto.rc;

import com.canin.crypto.util.Paddings;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.RC532Engine;
import org.bouncycastle.crypto.engines.RC564Engine;
import org.bouncycastle.crypto.paddings.*;
import org.bouncycastle.crypto.params.RC5Parameters;

import java.util.Arrays;

public class RC5Tool {
    //ecb
    private BufferedBlockCipher bufferedBlockCipher;
    private BlockCipherPadding blockCipherPadding;
    private final byte[] key;//The key must have a length of 0-2040
    private final Paddings padding;

    private final boolean isEncryption;

    private final int w;//字长

    private final int r;//轮数

    public RC5Tool(boolean isEncryption, byte[] key, Paddings padding, int w, int r) {
        this.isEncryption = isEncryption;
        this.key = key;
        this.padding = padding;
        this.w = w;
        this.r = r;
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
        if (w == 32) {
            if (blockCipherPadding != null) {
                bufferedBlockCipher = new PaddedBufferedBlockCipher(new RC532Engine());
            } else {
                bufferedBlockCipher = new BufferedBlockCipher(new RC532Engine());
            }
        } else if (w == 64) {
            if (blockCipherPadding != null) {
                bufferedBlockCipher = new PaddedBufferedBlockCipher(new RC564Engine());
            } else {
                bufferedBlockCipher = new BufferedBlockCipher(new RC564Engine());
            }
        } else {
            throw new RuntimeException("字长/w 必须得为32或64");
        }
    }
    public byte[] processingBytes(byte[] data) {
        init();
        bufferedBlockCipher.init(isEncryption, new RC5Parameters(key, r));
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
