package com.unitn.crypto.sslimpl.util;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import com.unitn.crypto.sslimpl.certificate.Certificate;
import com.unitn.crypto.sslimpl.certificate.ServerCertificate;

public class CryptoUtil {
	
	private static Map<String, AlgorithmParameters> parameters = null;
	
	public static AlgorithmParameters getAlgorithmParameters(Cipher cipher, String algo){
		if(CryptoUtil.parameters == null){
			CryptoUtil.parameters = new HashMap<String, AlgorithmParameters>();
		}
		// if not already present insert and return otherwise just return
		if(!CryptoUtil.parameters.containsKey(algo)){
			CryptoUtil.parameters.put(algo, cipher.getParameters());
		}
		return CryptoUtil.parameters.get(algo);
	}

	public static byte[] createSignatureForBuffer(Certificate certificate, byte[] buffer){
	    // self signing process
		Signature dsa;
		try {
			String algo = certificate.getDigitalSignatureAlgo();
			dsa = Signature.getInstance(algo);
			dsa.initSign(certificate.getDigitalSignaturePrivateK());
			dsa.update(buffer);
			return dsa.sign();
		} catch (NoSuchAlgorithmException e) {
			System.out.println("createSignatureForBuffer - NoSuchAlgorithmException");
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			System.out.println("createSignatureForBuffer - InvalidKeyException");
			e.printStackTrace();
		} catch (SignatureException e) {
			System.out.println("createSignatureForBuffer - SignatureException");
			e.printStackTrace();
		}
		return null;
	}
	
	
	public static void validateSignatureForBuffer(byte[] signature, byte[] totalInfo, PublicKey key, String signAlgo) throws Exception {
		boolean verifies = false;
		Signature dsa;
		dsa = Signature.getInstance(signAlgo);
		dsa.initVerify(key);
		dsa.update(totalInfo);
		verifies = dsa.verify(signature);
		if(verifies){
			System.out.println("Signature verified.");
		}
		else{
			throw new Exception("Signature not valid");
		}
	}

	//		Every implementation of the Java platform is required to support the following standard Cipher transformations with the keysizes in parentheses:
	//			AES/CBC/NoPadding (128)
	//			AES/CBC/PKCS5Padding (128)
	//			AES/ECB/NoPadding (128)
	//			AES/ECB/PKCS5Padding (128)
	//			DES/CBC/NoPadding (56)
	//			DES/CBC/PKCS5Padding (56)
	//			DES/ECB/NoPadding (56)
	//			DES/ECB/PKCS5Padding (56)
	//			DESede/CBC/NoPadding (168)
	//			DESede/CBC/PKCS5Padding (168)
	//			DESede/ECB/NoPadding (168)
	//			DESede/ECB/PKCS5Padding (168)
	//			RSA/ECB/PKCS1Padding (1024, 2048)
	//			RSA/ECB/OAEPWithSHA-1AndMGF1Padding (1024, 2048)
	//			RSA/ECB/OAEPWithSHA-256AndMGF1Padding (1024, 2048)
	public static SecretKey generateSymmetricKey(String algo, Certificate cert, PublicKey publicKey) {
		// if this trigger the algorithm is not supported
		if(algo.indexOf('/') == -1){
			System.out.println("generateSymmetricKey - Algorithm format not supported");
			return null;
		} 
		algo = algo.substring(0, algo.indexOf('/'));
		try {
			KeyAgreement kA = KeyAgreement.getInstance(cert.getKeyAgreementAlgo());
			kA.init(cert.getKeyAgreementPrivateK());
			kA.doPhase(publicKey,true);
	        return kA.generateSecret(algo);
		} catch (NoSuchAlgorithmException e) {
			System.out.println("generateSymmetricKey - NoSuchAlgorithmException");
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			System.out.println("generateSymmetricKey - InvalidKeyException");
			e.printStackTrace();
		}
        return null;
	}	
	
	public static byte[] encryptText(String algo, SecretKey secretKey, String plaintext){
		try {
			Cipher cipher = Cipher.getInstance(algo);
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, CryptoUtil.getAlgorithmParameters(cipher, algo));
	        // dumb padding, just add spaces to the end of the text 'till we reach multiple of 8
			while(plaintext.getBytes().length % 8 != 0){
				plaintext = plaintext + " ";
			}
			return cipher.doFinal(plaintext.getBytes());
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	public static String decryptText(String algo, SecretKey secretKey, byte[] cipherText){
		try {
	        // Initialize decryption
			Cipher cipher = Cipher.getInstance(algo);
			cipher.init(Cipher.DECRYPT_MODE, secretKey, CryptoUtil.getAlgorithmParameters(cipher, algo));
	        // Decrypt
	        byte[] decipheredText = cipher.doFinal(cipherText);
	        return new String(decipheredText);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
}
