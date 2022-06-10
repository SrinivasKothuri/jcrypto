package org.jcrypto.pki;

import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;

import static org.junit.Assert.assertTrue;

public class SignerVerifierTest {

	@Test
	public void testSignAndVerify() throws Exception {
		String testData = "Srinivas";

		KeyPair keyPair = new KeyPairCreator.Builder().withKeySize(2048).withAlgorithm("RSA").build().create();
		byte[] md5withRSAS = new Signer().algorithm("MD5withRSA").privateKey(keyPair.getPrivate())
				.sign(new ByteArrayInputStream(testData.getBytes(StandardCharsets.UTF_8)));

		assertTrue(new Verifier().algorithm("MD5withRSA").publicKey(keyPair.getPublic())
				.verify(new ByteArrayInputStream(testData.getBytes(StandardCharsets.UTF_8)), md5withRSAS));
	}
}
