package com.canin.crypto.sm;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.gm.SM2P256V1Curve;

import java.math.BigInteger;

public class SM2Constant {
    //推荐椭圆曲线参数
    public static final SM2P256V1Curve CURVE = new SM2P256V1Curve();
    public final static BigInteger P = CURVE.getQ();
    public final static BigInteger A = CURVE.getA().toBigInteger();
    public final static BigInteger B = CURVE.getB().toBigInteger();
    public final static BigInteger N = CURVE.getOrder();
    public final static BigInteger H = CURVE.getCofactor();
    public final static BigInteger GX = new BigInteger("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16);
    public final static BigInteger GY = new BigInteger("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16);
    public static final ECPoint G_POINT = CURVE.createPoint(GX, GY);
    public static final ECDomainParameters DOMAIN_PARAMS = new ECDomainParameters(CURVE, G_POINT, N, H);
}
