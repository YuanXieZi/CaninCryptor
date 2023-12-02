package com.canin.crypto.rsa;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;


public class RSATool {
    //默认PKCS1 Padding
    private final int keySize;

    private final int maxEncryptBlock;

    private final int maxDecryptBlock;

    private Key publicKey;

    private Key privateKey;

    public RSATool(int keySize) {
        this(keySize, null, null);
    }


    public RSATool(int keySize, Key publickKey, Key privateKey) {
        this.keySize = keySize;
        this.publicKey = publickKey;
        this.privateKey = privateKey;
        maxEncryptBlock = keySize / 8 - 11;
        maxDecryptBlock = keySize / 8;
    }

    public static Key getPublicKeyFromPemFile(String path) throws Exception {
        PemReader pemReader = new PemReader(new InputStreamReader(Files.newInputStream(Paths.get(path))));
        PemObject pemObject = pemReader.readPemObject();
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(pemObject.getContent());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(publicKeySpec);
    }

    public static Key getPrivateKeyFromPemFile(String path) throws Exception {
        PemReader pemReader = new PemReader(new InputStreamReader(Files.newInputStream(Paths.get(path))));
        PemObject pemObject = pemReader.readPemObject();
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(pemObject.getContent());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(privateKeySpec);
    }

    public void initKey() throws NoSuchAlgorithmException {
        if (publicKey == null || privateKey == null) {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(keySize);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            publicKey = keyPair.getPublic();
            privateKey = keyPair.getPrivate();
        }
    }

    public void saveKey(String publicKeyOutPath, String privateKeyOutPath) {
        File publicKeyOutFile = new File(publicKeyOutPath);
        File privateKeyOutFile = new File(privateKeyOutPath);
        if (!publicKeyOutFile.exists()) {
            publicKeyOutFile.getParentFile().mkdirs();
        }
        if (!privateKeyOutFile.exists()) {
            privateKeyOutFile.getParentFile().mkdirs();
        }
        PemWriter publicKeyWriter;
        PemWriter privateKeyWriter;
        try {
            publicKeyWriter = new PemWriter(new FileWriter(publicKeyOutFile));
            publicKeyWriter.writeObject(new PemObject("PUBLIC KEY", publicKey.getEncoded()));
            publicKeyWriter.close();
            privateKeyWriter = new PemWriter(new FileWriter(privateKeyOutFile));
            privateKeyWriter.writeObject(new PemObject("PRIVATE KEY", privateKey.getEncoded()));
            privateKeyWriter.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] processingBytes(boolean isEncryption, byte[] data) throws Exception {
        if (isEncryption) {
            return encrypt(data);
        }
        return decrypt(data);
    }

    private byte[] encrypt(byte[] data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        int dataLength = data.length;
        for (int i = 0, processedLength = 0; dataLength - processedLength > 0; i++, processedLength = i * maxEncryptBlock) {
            if (dataLength - processedLength > maxEncryptBlock) {
                stream.write(cipher.doFinal(data, processedLength, maxEncryptBlock));
            } else {
                stream.write(cipher.doFinal(data, processedLength, dataLength - processedLength));
            }
        }
        return stream.toByteArray();
    }

    private byte[] decrypt(byte[] data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        int dataLength = data.length;
        for (int i = 0, processedLength = 0; dataLength - processedLength > 0; i++, processedLength = i * maxDecryptBlock) {
            if (dataLength - processedLength > maxDecryptBlock) {
                stream.write(cipher.doFinal(data, processedLength, maxDecryptBlock));
            } else {
                stream.write(cipher.doFinal(data, processedLength, dataLength - processedLength));
            }
        }
        return stream.toByteArray();
    }

}
