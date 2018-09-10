package com.unitn.crypto.sslimpl.certificate;

import java.security.PublicKey;

public class ClientCertificate extends Certificate{

	private PublicKey serverKeyAgreementPK;
	private PublicKey serverDigitalSignaturePK;

	public void setServerKeyAgreementPK(PublicKey keyAgreementPK) {
		this.serverKeyAgreementPK = keyAgreementPK;
	}

	public void setServerDigitalSignaturePK(PublicKey digitalSignaturePK) {
		this.serverDigitalSignaturePK = digitalSignaturePK;
	}

	public PublicKey getServerKeyAgreementPK() {
		return serverKeyAgreementPK;
	}

	public PublicKey getServerDigitalSignaturePK() {
		return serverDigitalSignaturePK;
	}
	
}
