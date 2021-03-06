package org.jcrypto.pki;

import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

public class Verifier extends CommonAttributes.Builder<Verifier> {

	private String fAlgorithm;
	private PublicKey fPublicKey;

	public Verifier publicKey(PublicKey publicKey) {
		fPublicKey = publicKey;
		return this;
	}

	public Verifier algorithm(String algorithm) {
		this.fAlgorithm = algorithm;
		return this;
	}

	public boolean verify(InputStream inputStream, byte[] signatureBytes) throws NoSuchAlgorithmException,
			NoSuchProviderException, IOException, SignatureException, InvalidKeyException {
		checkDefaults();
		Signature signature;
		if (!StringUtils.isBlank(fProvider))
			signature = Signature.getInstance(fAlgorithm, fProvider);
		else
			signature = Signature.getInstance(fAlgorithm);

		signature.initVerify(fPublicKey);
		byte[] buffer = new byte[4096];
		int read;

		try {
			while ((read = inputStream.read(buffer)) >= 0)
				signature.update(buffer, 0, read);
		}
		finally {
			inputStream.close();
		}
		return signature.verify(signatureBytes);
	}

	@Override
	protected void checkDefaults() {
		if (fAlgorithm == null)
			throw new IllegalArgumentException("Algorithm is not specified to generate Verifier");
		if (fPublicKey == null)
			throw new IllegalArgumentException("Public key is not specified to generate Verifier");
	}
}
