package org.jcrypto.symmetric;

import org.apache.commons.lang3.StringUtils;
import org.jcrypto.pki.CommonAttributes;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;

public class SymmetricKeyCreator {

	public static class SymmetricKey {
		private final SecretKeySpec fSecretKey;
		private final Cipher fCipher;

		public SymmetricKey(SecretKeySpec fSecretKey, Cipher fCipher) {
			this.fSecretKey = fSecretKey;
			this.fCipher = fCipher;
		}

		public SecretKeySpec getSecretKey() {
			return fSecretKey;
		}

		public Cipher getCipher() {
			return fCipher;
		}
	}

	public static class Builder extends CommonAttributes.Builder {
		private String fAlgorithm;

		public Builder withAlgorithm(String algorithm) {
			fAlgorithm = algorithm;
			return this;
		}

		@Override
		protected void checkDefaults() {
			if (StringUtils.isBlank(fAlgorithm))
				throw new IllegalArgumentException("Algorithm is not be specified to generate Key");
		}
	}

	public static SymmetricKey create(String secret, int length, String algorithm) throws NoSuchAlgorithmException {
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(algorithm);
		return new SymmetricKey(null, null);
	}
}
