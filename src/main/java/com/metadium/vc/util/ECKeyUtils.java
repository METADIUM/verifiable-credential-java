package com.metadium.vc.util;

import java.math.BigInteger;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.util.Arrays;

/**
 * ECKey Utility.
 * @author mansud
 *
 */
public class ECKeyUtils {
	/**
	 * Convert from BigInteger to ECPrivateKey 
	 * @param privateKey private key
	 * @param curveName EC curve name
	 * @return EC private key
	 */
	public static BCECPrivateKey toECPrivateKey(BigInteger privateKey, String curveName) {
        ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec(curveName);
        EllipticCurve ellipticCurve = EC5Util.convertCurve(params.getCurve(), params.getSeed());

        ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(privateKey, EC5Util.convertSpec(ellipticCurve, params));
        return new BCECPrivateKey("EC", privateKeySpec, BouncyCastleProvider.CONFIGURATION);
	}
	
	/**
	 * Convert from BigIntger to ECPublicKey
	 * @param publicKey public key
	 * @param curveName EC curve name
	 * @return EC public key
	 */
	public static BCECPublicKey toECPublicKey(BigInteger publicKey, String curveName) {
        byte[] uncompressedPublicKey = Arrays.prepend(Numeric.toBytesPadded(publicKey, 64), (byte)0x04);
        return toECPublicKey(uncompressedPublicKey, curveName);
	}
	
	/**
	 * Convert from encoded public key to ECPublicKey
	 * @param encodedPublicKey encoded public key. (compressed or uncompressed)
	 * @param curveName EC curve name
	 * @return EC public key
	 */
	public static BCECPublicKey toECPublicKey(byte[] encodedPublicKey, String curveName) {
        ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec(curveName);
        EllipticCurve ellipticCurve = EC5Util.convertCurve(params.getCurve(), params.getSeed());

        ECPoint ecPoint = ECPointUtil.decodePoint(ellipticCurve, encodedPublicKey);
        ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(ecPoint, EC5Util.convertSpec(ellipticCurve, params));
        return new BCECPublicKey("EC", publicKeySpec, BouncyCastleProvider.CONFIGURATION);
	}

	/**
	 * Generate public key with private key
	 * @param privateKey private key
	 * @param curveName EC curve name
	 * @return public key
	 */
	public static BigInteger getPublicKeyFromPrivateKey(BigInteger privateKey, String curveName) {
		ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec(curveName);
		ECDomainParameters curve = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());
        if (privateKey.bitLength() > curve.getN().bitLength()) {
        	privateKey = privateKey.mod(curve.getN());
        }
        
        byte[] uncompressedPublicKey = new FixedPointCombMultiplier().multiply(curve.getG(), privateKey).getEncoded(false);
        return new BigInteger(1, Arrays.copyOfRange(uncompressedPublicKey, 1, uncompressedPublicKey.length));
	}
	
	/**
	 * Encode public key
	 * @param publicKey public key
	 * @return encoded public key
	 */
	public static byte[] encodePublicKey(BCECPublicKey publicKey) {
		return publicKey.getQ().getEncoded(false);
	}
	
	
}
