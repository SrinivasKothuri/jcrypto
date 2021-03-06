package org.jcrypto.pki;

import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;

public class Signer extends CommonAttributes.Builder<Signer> {

	private String fAlgorithm;
	private PrivateKey fPrivateKey;

	public Signer privateKey(PrivateKey privateKey) {
		fPrivateKey = privateKey;
		return this;
	}

	public Signer algorithm(String algorithm) {
		this.fAlgorithm = algorithm;
		return this;
	}

	public byte[] sign(InputStream inputStream) throws NoSuchAlgorithmException, NoSuchProviderException, IOException,
			SignatureException, InvalidKeyException {
		checkDefaults();
		Signature signature;
		if (!StringUtils.isBlank(fProvider))
			signature = Signature.getInstance(fAlgorithm, fProvider);
		else
			signature = Signature.getInstance(fAlgorithm);

		if (fSecureRandom != null)
			signature.initSign(fPrivateKey, fSecureRandom);
		else
			signature.initSign(fPrivateKey);

		byte[] buffer = new byte[4096];
		int read;

		try {
			while ((read = inputStream.read(buffer)) >= 0)
				signature.update(buffer, 0, read);
		}
		finally {
			inputStream.close();
		}
		return signature.sign();
	}

	@Override
	protected void checkDefaults() {
		if (fAlgorithm == null)
			throw new IllegalArgumentException("Algorithm is not specified to generate Signer");
		if (fPrivateKey == null)
			throw new IllegalArgumentException("Private key is not specified to generate Signer");
	}
}
