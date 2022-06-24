package org.jcrypto.symmetric;

public class StandardNames {
	public enum CipherAlgorithmName {
		AES, DES
	}
	public enum CipherAlgorithmMode {
		NONE, CBC, CFB, CFBx, CTR, CTS, ECB, OFB, OFBx, PCBC
	}
	public enum CipherAlgorithmPadding {
		NoPadding, ISO10126Padding, OAEPPadding, PKCS1Padding, PKCS5Padding, SSL3Padding, OAEPPadding
	}
}
