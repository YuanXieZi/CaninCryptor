package com.canin.crypto.sm;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;

import java.io.IOException;
import java.io.OutputStream;
import java.security.SecureRandom;

public class SM2Tool {

    private ECPublicKeyParameters ecPublicKeyParameters;

    private ECPrivateKeyParameters ecPrivateKeyParameters;

    private final SM2Engine.Mode mode;

    public SM2Tool(SM2Engine.Mode mode) {
        this(mode, null, null);
    }

    public SM2Tool(SM2Engine.Mode mode, ECPublicKeyParameters ecPublicKeyParameters, ECPrivateKeyParameters ecPrivateKeyParameters) {
        this.ecPublicKeyParameters = ecPublicKeyParameters;
        this.ecPrivateKeyParameters = ecPrivateKeyParameters;
        this.mode = mode;
    }


    public void initKey() {
        SecureRandom random = new SecureRandom();
        ECKeyGenerationParameters keyGenerationParams = new ECKeyGenerationParameters(SM2Constant.DOMAIN_PARAMS, random);
        ECKeyPairGenerator keyGen = new ECKeyPairGenerator();
        keyGen.init(keyGenerationParams);
        AsymmetricCipherKeyPair keyPair = keyGen.generateKeyPair();
        ecPublicKeyParameters = (ECPublicKeyParameters) keyPair.getPublic();
        ecPrivateKeyParameters = (ECPrivateKeyParameters) keyPair.getPrivate();
    }

    public void saveKey(OutputStream outputStream) throws IOException {
        outputStream.write(0);
        byte[] affineXCoord = ecPublicKeyParameters.getQ().getAffineXCoord().getEncoded();
        outputStream.write(int32ToByteArray(affineXCoord.length));
        outputStream.write(affineXCoord);
        outputStream.write(1);
        byte[] affineYCoord = ecPublicKeyParameters.getQ().getAffineYCoord().getEncoded();
        outputStream.write(int32ToByteArray(affineYCoord.length));
        outputStream.write(affineYCoord);
        outputStream.write(2);
        byte[] d = ecPrivateKeyParameters.getD().toByteArray();
        outputStream.write(int32ToByteArray(d.length));
        outputStream.write(d);
        outputStream.close();
    }

    private byte[] int32ToByteArray(int i) {
        byte[] bytes = new byte[4];
        for (int j = 0; j < 4; j++) {
            bytes[j] = (byte) ((i >> (8 * j)) & 0xFF);
        }
        return bytes;
    }


    public byte[] processingBytes(boolean isEncryption, byte[] data) throws InvalidCipherTextException {
        if (ecPublicKeyParameters == null || ecPrivateKeyParameters == null) {
            initKey();
        }
        SM2Engine engine = new SM2Engine(mode);
        if (isEncryption) {
            ParametersWithRandom parametersWithRandom = new ParametersWithRandom(ecPublicKeyParameters, new SecureRandom());
            engine.init(true, parametersWithRandom);
            return engine.processBlock(data, 0, data.length);
        }
        engine.init(false, ecPrivateKeyParameters);
        return engine.processBlock(data, 0, data.length);
    }

}
