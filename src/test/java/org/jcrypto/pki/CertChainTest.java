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

		X509Certificate rootX509Certificate = new X509CertificateCreator.Builder()
				.withPrivateKey(rootKeyPair.getPrivate())
				.withSigningAlgorithm("SHA256withRSA")
				.withIssuer(ImmutableMap.of(CertAttr.CN, "skothuri", CertAttr.C, "IN", CertAttr.O, "SN"))
				.withSubject(ImmutableMap.of(CertAttr.CN, "skothuri", CertAttr.C, "IN", CertAttr.O, "SN"))
				.withValidityStart(new Date())
				.withValidityEnd(JCryptoUtil.daysFromNow(365))
				.build().create(rootKeyPair.getPublic());

		X509Certificate childX509Certificate = new X509CertificateCreator.Builder()
				.withPrivateKey(rootKeyPair.getPrivate())
				.withSigningAlgorithm("SHA256withRSA")
				.withIssuer(ImmutableMap.of(CertAttr.CN, "skothuri", CertAttr.C, "IN", CertAttr.O, "SN"))
				.withSubject(ImmutableMap.of(CertAttr.CN, "localhost", CertAttr.C, "IN", CertAttr.O, "SN"))
				.withValidityStart(new Date())
				.withValidityEnd(JCryptoUtil.daysFromNow(365))
				.build().create(childKeyPair.getPublic());

		childX509Certificate.verify(rootKeyPair.getPublic());

		String destDir = "/Users/srinivas.kothuri/Desktop/certs";
		JCryptoUtil.storePEMCertificate(destDir, "root.cer", rootX509Certificate.getEncoded());
		JCryptoUtil.storePEMCertificate(destDir, "child.cer", childX509Certificate.getEncoded());
		JCryptoUtil.storePEMPrivateKey(destDir, "child.key", childKeyPair.getPrivate().getEncoded());
	}
}
