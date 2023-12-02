package com.canin.crypto.des;

import com.canin.crypto.util.Paddings;
import com.canin.crypto.util.WorkMode;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.modes.OFBBlockCipher;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.paddings.*;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.util.Arrays;

public class TripleDESTool {
    private BlockCipherPadding blockCipherPadding;
    private BlockCipher blockCipher;

    private boolean isEncryption;

    private byte[] key;//length must be 16 or 24
    private byte[] iv;//length must be 8

    private void setKeyAndIv(byte[] key, byte[] iv) {
        this.key = key;
        this.iv = iv;
    }

    private void initPadding(Paddings padding) {
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
    }

    public TripleDESTool(boolean isEncryption, byte[] key, byte[] iv, WorkMode workMode, Paddings padding, int refluxBits) {
        this.isEncryption = isEncryption;
        initPadding(padding);
        setKeyAndIv(key, iv);
        if (workMode != null) {
            switch (workMode) {
                case ECB:
                    blockCipher = new DESedeEngine();
                    break;
                case CBC:
                    blockCipher = new CBCBlockCipher(new DESedeEngine());
                    break;
                case CTR:
                    blockCipher = new SICBlockCipher(new DESedeEngine());
                    break;
                case CFB:
                    blockCipher = new CFBBlockCipher(new DESedeEngine(), refluxBits);
                    break;
                case OFB:
                    blockCipher = new OFBBlockCipher(new DESedeEngine(), refluxBits);
                    break;
                default:
            }
        }
    }

    public TripleDESTool(boolean isEncryption, byte[] key, byte[] iv, WorkMode workMode, Paddings padding) {
        this(isEncryption, key, iv, workMode, padding, 8);
    }

    public byte[] processingBytes(byte[] data) {
        BufferedBlockCipher cipher = getBufferedBlockCipher();
        int minSize = cipher.getOutputSize(data.length);
        byte[] outBuf = new byte[minSize];
        int blocksLength = cipher.processBytes(data, 0, data.length, outBuf, 0);
        try {
            int lastBlockLength = cipher.doFinal(outBuf, blocksLength);
            if (outBuf.length == (blocksLength + lastBlockLength)) {
                return outBuf;
            }
            return Arrays.copyOf(outBuf, blocksLength + lastBlockLength);
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException(e);
        }
    }

    private BufferedBlockCipher getBufferedBlockCipher() {
        BufferedBlockCipher cipher;
        if (blockCipherPadding == null) {
            cipher = new BufferedBlockCipher(blockCipher);
        } else {
            cipher = new PaddedBufferedBlockCipher(blockCipher, blockCipherPadding);
        }
        CipherParameters password;
        if (iv == null) {
            password = new KeyParameter(key);
        } else {
            password = new ParametersWithIV(new KeyParameter(key), iv);
        }
        cipher.init(isEncryption, password);
        return cipher;
    }
}
