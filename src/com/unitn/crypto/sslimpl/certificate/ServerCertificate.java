package com.unitn.crypto.sslimpl.certificate;

import java.security.PublicKey;

public class ServerCertificate extends Certificate {
	
	private PublicKey clientKeyAgreementPK;

	public PublicKey getClientKeyAgreementPK() {
		return clientKeyAgreementPK;
	}

	public void setClientKeyAgreementPK(PublicKey clientKeyAgreementPK) {
		this.clientKeyAgreementPK = clientKeyAgreementPK;
	}
	
}
