package com.unitn.crypto.sslimpl.certificate;

import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import com.unitn.crypto.sslimpl.util.FileUtil;

public class Certificate {

	private KeyPair keyAgreementPair;
	private KeyPair digitalSignaturePair;
	private String digitalSignatureAlgo;
	private String keyAgreementAlgo;

	public Certificate() {
		super();
	}

	public void getNewCertificate(String digitalSignatureAlgo, String keyAgreementAlgo) throws NoSuchAlgorithmException {
			SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
			// first write algorithms
			this.setDigitalSignatureAlgo(digitalSignatureAlgo);
			this.setKeyAgreementAlgo(keyAgreementAlgo);
			// generate key agreement pair
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyAgreementAlgo);
			keyPairGenerator.initialize(1024, random);
			this.setKeyAgreementPair(keyPairGenerator.genKeyPair());
			// generate signature pair 
			// NB: supported signature are 
	//		SHA1withDSA
	//		SHA1withRSA
	//		SHA256withRSA
			// so just take last 3 chars as key generator algo
			keyPairGenerator = KeyPairGenerator.getInstance(digitalSignatureAlgo.substring(digitalSignatureAlgo.length()-3));
			keyPairGenerator.initialize(1024, random);
			this.setDigitalSignaturePair(keyPairGenerator.genKeyPair());
		}

	public PublicKey getKeyAgreementPK() {
		return keyAgreementPair.getPublic();
	}

	private void setKeyAgreementPair(KeyPair keyAgreementPair) {
		this.keyAgreementPair = keyAgreementPair;
	}

	public PublicKey getDigitalSignaturePK() {
		return digitalSignaturePair.getPublic();
	}

	private void setDigitalSignaturePair(KeyPair digitalSignaturePair) {
		this.digitalSignaturePair = digitalSignaturePair;
	}

	public String getDigitalSignatureAlgo() {
		return digitalSignatureAlgo;
	}

	public void setDigitalSignatureAlgo(String digitalSignatureAlgo) {
		this.digitalSignatureAlgo = digitalSignatureAlgo;
	}

	public String getKeyAgreementAlgo() {
		return keyAgreementAlgo;
	}

	public void setKeyAgreementAlgo(String keyAgreementAlgo) {
		this.keyAgreementAlgo = keyAgreementAlgo;
	}

	public void printCertificate(String fileName) throws IOException {
		FileUtil.printCertificate(this, fileName);
	}

	public PrivateKey getDigitalSignaturePrivateK() {
		return this.digitalSignaturePair.getPrivate();
	}

	public Key getKeyAgreementPrivateK() {
		return this.keyAgreementPair.getPrivate();
	}

}