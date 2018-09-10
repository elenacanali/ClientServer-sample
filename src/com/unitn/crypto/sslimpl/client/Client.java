package com.unitn.crypto.sslimpl.client;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;

import javax.crypto.SecretKey;

import com.unitn.crypto.sslimpl.certificate.ClientCertificate;
import com.unitn.crypto.sslimpl.certificate.ServerCertificate;
import com.unitn.crypto.sslimpl.util.ConversionUtil;
import com.unitn.crypto.sslimpl.util.CryptoUtil;
import com.unitn.crypto.sslimpl.util.FileUtil;

public class Client {
	
	private ClientCertificate cert;
	private List<String> supportedCiphers;
	private List<String> serverSupportedCiphers;
	private String selectedCipher = "";
	private SecretKey symmetricKey = null;
	
	public Client() throws Exception{
		// TODO take from input
		this.generateSupportedCiphers();
		// read certificate from server
		this.readServerCertificate();
		// load supported ciphers from server
		this.loadServerSupportedCiphers();
	}
	
	public Client(List<String> clientCiphers) throws Exception {
		this.supportedCiphers = clientCiphers;
		// read certificate from server
		this.readServerCertificate();
		// load supported ciphers from server
		this.loadServerSupportedCiphers();
	}

	private void loadServerSupportedCiphers() {
		this.serverSupportedCiphers = FileUtil.loadServerSupportedCiphers();
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
				this.supportedCiphers.add("AES/CBC/NoPadding");
				this.supportedCiphers.add("DESede/CBC/PKCS5Padding");
				this.supportedCiphers.add("DESede/ECB/PKCS5Padding");
				this.supportedCiphers.add("DES/CBC/NoPadding");
	}
	
	private void readServerCertificate() throws Exception{
		cert = FileUtil.readCertificate("serverCertificate.txt");
		System.out.println("CLIENT created with associated certificate");
	}

	public void createHandshake() throws IOException {
		FileUtil.printHandShake(cert, supportedCiphers);
	}

	public void generateSymmetricKey() {
		List<String> common = ConversionUtil.getCommonElements(this.supportedCiphers, this.serverSupportedCiphers);
		if(common.isEmpty()){
			System.out.println("Something wrong. No common cipher!");
			return;
		}
		this.selectedCipher = common.get(0);
		this.symmetricKey = CryptoUtil.generateSymmetricKey(this.selectedCipher, this.cert, this.cert.getServerKeyAgreementPK());
	}
	
	public void sendMessage(String plainText) throws IOException{
		byte[] cipherText = CryptoUtil.encryptText(this.selectedCipher, this.symmetricKey, plainText);
		FileUtil.writeMessageToFile(cipherText);
	}
	
	public String readMessage(){
		byte[] cipherText = FileUtil.readMessage();
		return CryptoUtil.decryptText(this.selectedCipher, this.symmetricKey, cipherText);
	}
	
	public void requestChangeCipher() throws IOException{
		long seed = System.nanoTime();
		System.out.println("Client " + this.supportedCiphers);
		Collections.shuffle(this.supportedCiphers, new Random(seed));
		System.out.println("Next Client " + this.supportedCiphers);
		// send last message
		this.sendMessage("---ReqChangeingCipher---");
		// create handshake
		this.createHandshake();
		// client choose proper KA and generate symmetric key
		this.generateSymmetricKey();
		// send special message
	}
}
