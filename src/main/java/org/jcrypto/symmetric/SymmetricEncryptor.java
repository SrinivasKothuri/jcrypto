package org.jcrypto.symmetric;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Sets;
import org.apache.commons.lang3.StringUtils;
import org.jcrypto.pki.CommonAttributes;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Map;
import java.util.Set;

public class SymmetricEncryptor {

	private String algoName;
	private String mode;
	private String padding;
	private int keySize;
	private String provider;
	private SecureRandom secureRandom;

	private final Map<String, Set<Integer>> nameToKeySizesMap = ImmutableMap.of(
			StandardNames.CipherAlgorithmName.AES.name(), Sets.newHashSet(128, 192, 256)
	);

	public SecretKey create() throws NoSuchAlgorithmException, NoSuchProviderException {
		KeyGenerator keyGenerator;
		String algorithm = StringUtils.joinWith("/", new String[]{algoName, mode, padding});

		if (provider != null)
			keyGenerator = KeyGenerator.getInstance(algorithm, provider);
		else
			keyGenerator = KeyGenerator.getInstance(algorithm);

		if (secureRandom != null)
			keyGenerator.init(keySize, secureRandom);
		else
			keyGenerator.init(keySize);
		return null;
	}

	public static class KeyBuilder extends CommonAttributes {

		private String algoName;
		private String mode;
		private String padding;
		private int keySize;

		public KeyBuilder(String provider, SecureRandom secureRandom) {
			super(provider, secureRandom);
		}

		public KeyBuilder withCipherAlgorithm(String algoName) {
			this.algoName = algoName;
			return this;
		}

		public KeyBuilder withMode(String mode) {
			this.mode = mode;
			return this;
		}

		public KeyBuilder withPadding(String padding) {
			this.padding = padding;
			return this;
		}

		public KeyBuilder withKeySize(int keySize) {
			this.keySize = keySize;
			return this;
		}
	}

}
