package com.canin.crypto.rijndael;

import com.canin.crypto.util.Paddings;
import com.canin.crypto.util.WorkMode;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.RijndaelEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.modes.OFBBlockCipher;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.paddings.*;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.util.Arrays;

public class RijndaelTool {
    private BlockCipherPadding blockCipherPadding;
    private BlockCipher blockCipher;

    private boolean isEncryption;

    private byte[] key;//length must be 16 or 20 or 24 or 28 or 32
    private byte[] iv;//length must be 16 or 20 or 24 or 28 or 32

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

    public RijndaelTool(boolean isEncryption, byte[] key, byte[] iv, WorkMode workMode, Paddings padding, int keyBits, int refluxBits) {
        this.isEncryption = isEncryption;
        initPadding(padding);
        setKeyAndIv(key, iv);
        if (workMode != null) {
            switch (workMode) {
                case ECB:
                    blockCipher = new RijndaelEngine(keyBits);
                    break;
                case CBC:
                    blockCipher = new CBCBlockCipher(new RijndaelEngine(keyBits));
                    break;
                case CTR:
                    blockCipher = new SICBlockCipher(new RijndaelEngine(keyBits));
                    switch (keyBits) {
                        case 128:
                            if (iv.length < 8) {
                                throw new RuntimeException("iv至少为8位Bytes");
                            }
                            break;
                        case 160:
                            if (iv.length < 12) {
                                throw new RuntimeException("iv至少为12位Bytes");
                            }
                            break;
                        case 192:
                            if (iv.length < 16) {
                                throw new RuntimeException("iv至少为16位Bytes");
                            }
                            break;
                        case 224:
                            if (iv.length < 20) {
                                throw new RuntimeException("iv至少为20位Bytes");
                            }
                            break;
                        case 256:
                            if (iv.length < 24) {
                                throw new RuntimeException("iv至少为24位Bytes");
                            }
                        default:
                    }
                    break;
                case CFB:
                    blockCipher = new CFBBlockCipher(new RijndaelEngine(keyBits), refluxBits);
                    break;
                case OFB:
                    blockCipher = new OFBBlockCipher(new RijndaelEngine(keyBits), refluxBits);
                    break;
                default:
            }
        }
    }

    public RijndaelTool(boolean isEncryption, byte[] key, byte[] iv, WorkMode workMode, Paddings padding, int keyBits) {
        this(isEncryption, key, iv, workMode, padding, keyBits, 8);
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
