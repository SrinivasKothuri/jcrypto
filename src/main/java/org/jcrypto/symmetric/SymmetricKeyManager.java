package org.jcrypto.symmetric;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class SymmetricKeyManager {

	public static class SymmetricKey {
		private SecretKeySpec fSecretKey;
		private Cipher fCipher;
	}

	public static SymmetricKey create(String secret, int length, String algorithm) {

	}
}
