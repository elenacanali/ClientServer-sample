package com.unitn.crypto.sslimpl.server;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;

import javax.crypto.SecretKey;

import com.unitn.crypto.sslimpl.certificate.ServerCertificate;
import com.unitn.crypto.sslimpl.util.ConversionUtil;
import com.unitn.crypto.sslimpl.util.CryptoUtil;
import com.unitn.crypto.sslimpl.util.FileUtil;

/**
 * Il server legge in input un algoritmo di firma, 
 * uno di key agreement ed una lista di cifrari simmetrici, 
 * genera un certificato corrispondente e va a scrivere due file: 
 * il primo è l'omologo di un certificato X.509 
 * contenente le stringhe identificative di DS e KA 
 * con le corrispondenti chiavi pubbliche, 
 * self-signed dal server stesso; il secondo contiene 
 * la lista dei cifrari supportati.
 *
 */
public class Server {

	// hardcoded for now should come frome input
//	Every implementation of the Java platform is required to support the following standard Signature algorithms:
//		SHA1withDSA
//		SHA1withRSA
//		SHA256withRSA
	private String digitalSignatureAlgo = "SHA1withRSA";

	//	KeyAgreement Algorithms
//	DiffieHellman	Diffie-Hellman Key Agreement as defined in PKCS #3: Diffie-Hellman Key-Agreement Standard, RSA Laboratories, version 1.4, November 1993.
//	ECDH	Elliptic Curve Diffie-Hellman as defined in ANSI X9.63 and as described in RFC 3278: "Use of Elliptic Curve Cryptography (ECC) Algorithms in Cryptographic Message Syntax (CMS)."
//	ECMQV	Elliptic Curve Menezes-Qu-Vanstone as defined in "Elliptic Curve Cryptography" from www.secg.org
	private String keyAgreementAlgo = "DiffieHellman";
	private List<String> supportedCiphers;
	private List<String> clientSupportedCiphers;
	private String selectedCipher;
	private SecretKey symmetricKey = null;
	private ServerCertificate cert;
	
	private void createCertificate() throws IOException{
		try {
			this.cert = new ServerCertificate();
			this.cert.getNewCertificate(this.digitalSignatureAlgo, this.keyAgreementAlgo);
			this.cert.printCertificate("serverCertificate.txt");
			FileUtil.printCiphersList(this.supportedCiphers, "serverCiphers.txt");
			System.out.println("Server side agreement printed");
		} catch (NoSuchAlgorithmException e) {
			System.out.println("createCertificate - Selected algorithm does not exist");
			e.printStackTrace();
		}
	}
	
	public Server() throws IOException{
		// this should come from input
		this.generateSupportedCiphers();
		// init server side
		this.createCertificate();
	}

	public Server(String dsAlgo, String ksAlgo, List<String> serverCiphers) throws IOException {
		this.supportedCiphers = serverCiphers;
		this.keyAgreementAlgo = ksAlgo;
		this.digitalSignatureAlgo = dsAlgo;
		this.createCertificate();
	}

	private void generateSupportedCiphers() {
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
				this.supportedCiphers = new ArrayList<String>();
				this.supportedCiphers.add("DESede/CBC/PKCS5Padding");
				this.supportedCiphers.add("DESede/ECB/PKCS5Padding");
				this.supportedCiphers.add("DES/CBC/NoPadding");
	}

	public void readHandshake() {
		this.clientSupportedCiphers = FileUtil.readHandShake(this.cert);
	}

	public String generateSymmetricKey() throws Exception {
		List<String> common = ConversionUtil.getCommonElements(this.clientSupportedCiphers, this.supportedCiphers);
		if(common.isEmpty()){
			System.out.println("Something wrong. No common cipher!");
			throw new Exception("Something wrong. No common cipher!");
		}
		this.selectedCipher = common.get(0);
		System.out.println("Selected cipher: " + this.selectedCipher);
		this.symmetricKey = CryptoUtil.generateSymmetricKey(this.selectedCipher, this.cert, this.cert.getClientKeyAgreementPK());	
		return this.selectedCipher;
	}
	
	public void sendMessage(String plainText) throws IOException{
		byte[] cipherText = CryptoUtil.encryptText(this.selectedCipher, this.symmetricKey, plainText);
		FileUtil.writeMessageToFile(cipherText);
	}
	
	public String readMessage() throws Exception{
		byte[] cipherText = FileUtil.readMessage();
		String message = CryptoUtil.decryptText(this.selectedCipher, this.symmetricKey, cipherText);
		if(message.contentEquals("---ReqChangeingCipher---")){
			long seed = System.nanoTime();
			System.out.println("Server " + this.supportedCiphers);
			Collections.shuffle(this.supportedCiphers, new Random(seed));
			System.out.println("Next server " + this.supportedCiphers);
			this.readHandshake();
			// if I am reading the change cipher request return the decided cipher
			return this.generateSymmetricKey(); 
		}
		return message;
	}
	
}
