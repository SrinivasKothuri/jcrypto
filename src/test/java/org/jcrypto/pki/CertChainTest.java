package org.jcrypto.pki;

import com.google.common.collect.ImmutableMap;
import org.jcrypto.util.JCryptoUtil;
import org.jcrypto.util.JCryptoUtil.CertAttr;
import org.junit.Test;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;

import static org.apache.commons.lang3.StringUtils.EMPTY;

public class CertChainTest {

	static final ImmutableMap<CertAttr, String> EMPTY_NAME =
			ImmutableMap.of(CertAttr.CN, EMPTY, CertAttr.C, EMPTY, CertAttr.O, EMPTY);

	@Test
	public void createCertChainTest() throws Exception {
		KeyPair rootKeyPair = new KeyPairCreator.Builder().withAlgorithm("RSA").withKeySize(2048).build().create();
		KeyPair childKeyPair = new KeyPairCreator.Builder().withAlgorithm("RSA").withKeySize(2048).build().create();

		X509Certificate x509Certificate = new X509CertificateCreator.Builder()
				.withPrivateKey(rootKeyPair.getPrivate())
				.withSigningAlgorithm("SHA256withRSA")
				.withIssuer(EMPTY_NAME)
				.withSubject(EMPTY_NAME)
				.withValidityStart(new Date())
				.withValidityEnd(JCryptoUtil.daysFromNow(365))
				.build().create(childKeyPair.getPublic());

		x509Certificate.verify(rootKeyPair.getPublic());
	}
}
