package com.unitn.crypto.sslimpl.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import com.unitn.crypto.sslimpl.certificate.Certificate;
import com.unitn.crypto.sslimpl.certificate.ClientCertificate;
import com.unitn.crypto.sslimpl.certificate.ServerCertificate;

/**
 * This file take care of the print/read of files
 * 
 * NB: is really important that every certificate print respect this structure
 * concatenated in one single byte buffer:
 * 
 * size1 DigSigAlgo
 * size2 DigSigPubKey
 * size3 KeyAgreementAlgo
 * size4 KeyAgreementPubKey
 * 
 * @author 
 *
 */
public class FileUtil {
	
	public static final String pathToCertificate = "certificate/";
	public static final String pathToMessages = "message/";

	public static void printCertificate(Certificate certificate, String fileName) throws IOException {
		    // prepare byte array with all the informations:
			// concat for each information size (4 bytes) and then the info
			// DigSigAlgo:
		    byte[] buffer = {};
		    byte[] digSignAlgo = certificate.getDigitalSignatureAlgo().getBytes();
		    byte[] digSignAlgoSize = ConversionUtil.intToByteArray(digSignAlgo.length);
		    buffer = ConversionUtil.concatByteArrays(buffer, digSignAlgoSize);
		    buffer = ConversionUtil.concatByteArrays(buffer, digSignAlgo);
		    // DigSigPubKey:
		    byte [] digSigPubKeyEncoded = certificate.getDigitalSignaturePK().getEncoded();
		    byte [] digSigPubKeyEncodedSize = ConversionUtil.intToByteArray(digSigPubKeyEncoded.length);
		    buffer = ConversionUtil.concatByteArrays(buffer, digSigPubKeyEncodedSize);
		    buffer = ConversionUtil.concatByteArrays(buffer, digSigPubKeyEncoded);
		    // KeyAgreementAlgo:
		    byte[] keyAgreementAlgo = certificate.getKeyAgreementAlgo().getBytes();
		    byte[] keyAgreementAlgoSize = ConversionUtil.intToByteArray(keyAgreementAlgo.length);
		    buffer = ConversionUtil.concatByteArrays(buffer, keyAgreementAlgoSize);
		    buffer = ConversionUtil.concatByteArrays(buffer, keyAgreementAlgo);
		    // KeyAgreementPubKey:
		    byte [] keyAgreementPubKeyEncoded = certificate.getKeyAgreementPK().getEncoded();
		    byte [] keyAgreementPubKeyEncodedSize = ConversionUtil.intToByteArray(keyAgreementPubKeyEncoded.length);
		    buffer = ConversionUtil.concatByteArrays(buffer, keyAgreementPubKeyEncodedSize);
		    buffer = ConversionUtil.concatByteArrays(buffer, keyAgreementPubKeyEncoded);
	        
		    byte[] signature = CryptoUtil.createSignatureForBuffer(certificate, buffer);
		    byte[] signatureSize = ConversionUtil.intToByteArray(signature.length);
		    buffer = ConversionUtil.concatByteArrays(buffer, signatureSize);
		    buffer = ConversionUtil.concatByteArrays(buffer, signature);
	        
		    FileUtil.writeByteArrayToFile(buffer, pathToCertificate + fileName);
	}
	
	public static void printCiphersList(List<String> ciphers, String fileName) throws IOException {
		byte[] buffer = FileUtil.loadCipherListIntoBuffer(ciphers);
	    FileUtil.writeByteArrayToFile(buffer, pathToCertificate + fileName);
	}
	
	private static byte[] loadCipherListIntoBuffer(List<String> ciphers){
		byte[] buffer = {};
		return FileUtil.concatCipherListIntoBuffer(ciphers, buffer);
	}
	
	/**
	 * Given a buffer concat the byte value of the cipher list in the usal form:
	 * size value
	 * size value 
	 * ...
	 *
	 * @param ciphers
	 * @return
	 */
	private static byte[] concatCipherListIntoBuffer(List<String> ciphers, byte[] buffer){
		// first of all put into the biffer the number of ciphers supported
		byte[] cipherNumber = ConversionUtil.intToByteArray(ciphers.size());
	    buffer = ConversionUtil.concatByteArrays(buffer, cipherNumber);
	    // for each algo supported print into the buffer size and value
		Iterator<String> iter = ciphers.iterator();
	    while(iter.hasNext()){
	    	byte[] cipherAlgo = iter.next().getBytes();
	    	byte[] cipherAlgoSize = ConversionUtil.intToByteArray(cipherAlgo.length);
		    buffer = ConversionUtil.concatByteArrays(buffer, cipherAlgoSize);
		    buffer = ConversionUtil.concatByteArrays(buffer, cipherAlgo);
	    }
	    return buffer;
	}
	
	public static ClientCertificate readCertificate(String fileName) throws Exception{
			//ClientCertificate cert = new ClientCertificate();
			FileInputStream inputStream = new FileInputStream(new File(pathToCertificate + fileName));
			
			// I need a full byte array at the end with all the info
			byte[] totalInfo = {};
			
			// DigSigAlgo:
			byte[] byteSize = new byte [4];
			// read 4 bytes of size
			inputStream.read(byteSize);
			int size = ConversionUtil.byteArrayToInt(byteSize);
			byte[] byteDigSignAlgo = new byte[size];
			// read size bytes of string
			inputStream.read(byteDigSignAlgo);
			// add those to the total buffer
			totalInfo = ConversionUtil.concatByteArrays(totalInfo, byteSize);
			totalInfo = ConversionUtil.concatByteArrays(totalInfo, byteDigSignAlgo);
			String digSigAlgo = new String(byteDigSignAlgo);
			
			// DigSigPubKey:
			byteSize = new byte [4];
			// read 4 bytes of size
			inputStream.read(byteSize);
			size = ConversionUtil.byteArrayToInt(byteSize);
			byte[] byteDigSigPubKey = new byte[size];
			// read size bytes of encoded key
			inputStream.read(byteDigSigPubKey);
			// add those to the total buffer
			totalInfo = ConversionUtil.concatByteArrays(totalInfo, byteSize);
			totalInfo = ConversionUtil.concatByteArrays(totalInfo, byteDigSigPubKey);
			// using algo and encoded key create key
			// NB: supported signature are 
//			SHA1withDSA
//			SHA1withRSA
//			SHA256withRSA
			// so just take last 3 chars as key generator algo
    		KeyFactory keyFactory = KeyFactory.getInstance(digSigAlgo.substring(digSigAlgo.length()-3));
    		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(byteDigSigPubKey);
    		PublicKey serverDigSigPubKey = keyFactory.generatePublic(pubKeySpec);
    		
			// KeyAgreementAlgo:
			byteSize = new byte [4];
			// read 4 bytes of size
			inputStream.read(byteSize);
			size = ConversionUtil.byteArrayToInt(byteSize);
			byte[] byteKeyAgreementAlgo = new byte[size];
			// read size bytes of string
			inputStream.read(byteKeyAgreementAlgo);
			// add those to the total buffer
			totalInfo = ConversionUtil.concatByteArrays(totalInfo, byteSize);
			totalInfo = ConversionUtil.concatByteArrays(totalInfo, byteKeyAgreementAlgo);
			String keyAgreementAlgo = new String(byteKeyAgreementAlgo);
			
			// KeyAgreementPubKey:
			byteSize = new byte [4];
			// read 4 bytes of size
			inputStream.read(byteSize);
			size = ConversionUtil.byteArrayToInt(byteSize);
			byte[] byteKeyAgreementPubKey = new byte[size];
			// read size bytes of encoded key
			inputStream.read(byteKeyAgreementPubKey);
			// add those to the total buffer
			totalInfo = ConversionUtil.concatByteArrays(totalInfo, byteSize);
			totalInfo = ConversionUtil.concatByteArrays(totalInfo, byteKeyAgreementPubKey);
			// using algo and encoded key create key
    		keyFactory = KeyFactory.getInstance(keyAgreementAlgo);
    		pubKeySpec = new X509EncodedKeySpec(byteKeyAgreementPubKey);
    		PublicKey serverKeyAgreementPubKey = keyFactory.generatePublic(pubKeySpec);
    		
    		// there is the end of the information, next is signature
    		// Get Signature
    		byteSize = new byte [4];
			// read 4 bytes of size
			inputStream.read(byteSize);
			size = ConversionUtil.byteArrayToInt(byteSize);
			byte[] signature = new byte[size];
			// read size bytes of encoded key
			inputStream.read(signature);
			// TODO rise an exception if not validated!
			CryptoUtil.validateSignatureForBuffer(signature, totalInfo, serverDigSigPubKey, digSigAlgo);
			
			// assuming signature valid let's build the client certificate based on this
			ClientCertificate cert = new ClientCertificate();
			cert.getNewCertificate(digSigAlgo, keyAgreementAlgo);
			cert.setServerDigitalSignaturePK(serverDigSigPubKey);
			cert.setServerKeyAgreementPK(serverKeyAgreementPubKey);
			return cert;	
	}
	
	private static void writeByteArrayToFile(byte[] buffer, String fileName) throws IOException{
	    // create the file if it exists or not
	    FileOutputStream stream = new FileOutputStream(fileName, false);
	    stream.write(buffer);
	}
	
	public static void writeMessageToFile(byte[] buffer) throws IOException{
		byte[] size = ConversionUtil.intToByteArray(buffer.length);
		buffer = ConversionUtil.concatByteArrays(size, buffer);
		FileUtil.writeByteArrayToFile(buffer, FileUtil.pathToMessages + "exchange_messages.txt");
	}
	
	/**
	 * Structure printed handshake file
	 * 
	 * size publicKA
	 * number_of_ciphers
	 * size cipher1
	 * size cipher2
	 * size cipher3
	 * ...
	 * size ciphern
	 * 
	 * @param cert
	 * @param supportedCiphers 
	 * @throws IOException 
	 */
	public static void printHandShake(ClientCertificate cert, List<String> supportedCiphers) throws IOException {
//		Il client crea un file di 'handshake' contenente la propria chiave 
//		pubblica per il KA e la lista di cifrari supportati.
//		Allo stesso modo chi è da solo può lasciare anche 
//		la lista di cifrari del client fissa e scrivere in un altro file
//		la chiave pubblica per il KA
		// KA
		byte[] buffer = {};
		byte [] keyAgreementPubKeyEncoded = cert.getKeyAgreementPK().getEncoded();
	    byte [] keyAgreementPubKeyEncodedSize = ConversionUtil.intToByteArray(keyAgreementPubKeyEncoded.length);
	    buffer = ConversionUtil.concatByteArrays(buffer, keyAgreementPubKeyEncodedSize);
	    buffer = ConversionUtil.concatByteArrays(buffer, keyAgreementPubKeyEncoded);

	    // add the list to the buffer
	    buffer = FileUtil.concatCipherListIntoBuffer(supportedCiphers, buffer);
	    
	    // write the resulting buffer to the hankdshake file
	    FileUtil.writeByteArrayToFile(buffer, pathToCertificate + "handshake.txt");
	}

	public static List<String> loadServerSupportedCiphers() {
		List<String> result = new ArrayList<String>();
		try(FileInputStream inputStream = new FileInputStream(new File(pathToCertificate + "serverCiphers.txt"))) {
					// read number of ciphers supported
					byte[] listSize = new byte [4];
					inputStream.read(listSize);
					int listLength = ConversionUtil.byteArrayToInt(listSize);
					for(int i=0; i<listLength; i++){
						byte[] byteSize = new byte [4];
						inputStream.read(byteSize);
						int size = ConversionUtil.byteArrayToInt(byteSize);
						byte[] cipher = new byte[size];
						// read size bytes of string
						inputStream.read(cipher);
						// add those to the total buffer
						result.add(new String(cipher));
					}
		} catch (FileNotFoundException e) {
			System.out.println("loadServerSupportedCiphers - FileNotFound");
			e.printStackTrace();
		} catch (IOException e) {
			System.out.println("loadServerSupportedCiphers - IOException");
			e.printStackTrace();
		}
		return result;
	}

	public static List<String> readHandShake(ServerCertificate cert) {
		List<String> result = new ArrayList<String>();
		try(FileInputStream inputStream = new FileInputStream(new File(pathToCertificate + "handshake.txt"))) {
					// first of all read length and byte value of the KA of the client
					byte[] keySize = new byte [4];
					inputStream.read(keySize);
					int keyIntSize = ConversionUtil.byteArrayToInt(keySize);
					byte[] pubKey = new byte[keyIntSize];
					// read size bytes of encoded key
					inputStream.read(pubKey);
					// so just take last 3 chars as key generator algo
		    		KeyFactory keyFactory = KeyFactory.getInstance(cert.getKeyAgreementAlgo());
		    		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pubKey);
		    		// set it to the server certificate as client PK
		    		cert.setClientKeyAgreementPK(keyFactory.generatePublic(pubKeySpec));
					
		    		// GO for the ciphers
					// read number of ciphers supported
					byte[] listSize = new byte [4];
					inputStream.read(listSize);
					int listLength = ConversionUtil.byteArrayToInt(listSize);
					for(int i=0; i<listLength; i++){
						byte[] byteSize = new byte [4];
						inputStream.read(byteSize);
						int size = ConversionUtil.byteArrayToInt(byteSize);
						byte[] cipher = new byte[size];
						// read size bytes of string
						inputStream.read(cipher);
						// add those to the total buffer
						result.add(new String(cipher));
					}
		} catch (FileNotFoundException e) {
			System.out.println("loadServerSupportedCiphers - FileNotFound");
			e.printStackTrace();
		} catch (IOException e) {
			System.out.println("loadServerSupportedCiphers - IOException");
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return result;
	}

	public static byte[] readMessage() {
		try(FileInputStream inputStream = new FileInputStream(new File(FileUtil.pathToMessages + "exchange_messages.txt"))) {
			// first of all read length and byte value of the KA of the client
			byte[] byteSize = new byte [4];
			inputStream.read(byteSize);
			int size = ConversionUtil.byteArrayToInt(byteSize);
			byte[] cipherText = new byte[size];
			// read size bytes of encoded key
			inputStream.read(cipherText);
			// so just take last 3 chars as key generator algo
			return cipherText;
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	} 
	
}
