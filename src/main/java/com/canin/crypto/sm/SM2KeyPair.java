package com.canin.crypto.sm;

import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;

public class SM2KeyPair {
    private ECPublicKeyParameters publicKeyParameters;

    private ECPrivateKeyParameters privateKeyParameters;

    public ECPrivateKeyParameters getPrivateKeyParameters() {
        return privateKeyParameters;
    }

    public ECPublicKeyParameters getPublicKeyParameters() {
        return publicKeyParameters;
    }

    private void init(byte[] affineXCoord, byte[] affineYCoord, byte[] d) {
        publicKeyParameters = new ECPublicKeyParameters(SM2Constant.CURVE.createPoint(new BigInteger(1, affineXCoord), new BigInteger(1, affineYCoord)), SM2Constant.DOMAIN_PARAMS);
        privateKeyParameters = new ECPrivateKeyParameters(new BigInteger(1, d), SM2Constant.DOMAIN_PARAMS);
    }

    public SM2KeyPair(byte[] affineXCoord, byte[] affineYCoord, byte[] d) {
        init(affineXCoord, affineYCoord, d);
    }

    public SM2KeyPair(InputStream inputStream) throws IOException {
        byte[] affineXCoord = null, affineYCoord = null, d = null;
        int index = 0;
        byte[] lenBytes = new byte[4];
        for (int i = 0; i < 3; i++) {
            byte b = (byte) inputStream.read();
            index++;
            inputStream.read(lenBytes);
            index += 4;
            int length = bytesToInt(lenBytes);
            switch (b) {
                case (byte) 0 :
                    affineXCoord = new byte[length];
                    inputStream.read(affineXCoord);
                    break;
                case (byte) 1 :
                    affineYCoord = new byte[length];
                    inputStream.read(affineYCoord);
                    break;
                case (byte) 2:
                    d = new byte[length];
                    inputStream.read(d);
                    break;
                default:
                    break;
            }
            index += length;
        }
        inputStream.close();
        init(affineXCoord, affineYCoord, d);
    }

    private int bytesToInt(byte[] buf) {
        int r = 0;
        for (int i = 4 - 1; i >= 0; i--) {
            r <<= 8;
            r |= (buf[i] & 0x000000ff);
        }
        return r;
    }
}
