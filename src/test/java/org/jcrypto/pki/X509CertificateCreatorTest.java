package org.jcrypto.pki;

import com.google.common.collect.ImmutableMap;
import org.jcrypto.util.JCryptoUtil;
import org.jcrypto.util.JCryptoUtil.CertAttr;
import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.Map;

import static org.junit.Assert.assertEquals;

public class X509CertificateCreatorTest {
    @Test
    public void testSelfSignedX509CertificateCreation() throws Exception {
        ImmutableMap<CertAttr, String> subjectAndIssuer =
                ImmutableMap.of(CertAttr.CN, "skothuri.home.com", CertAttr.C, "IN", CertAttr.O, "Home");

        KeyPair keyPair = new KeyPairCreator.Builder().withKeySize(2048).withAlgorithm("RSA").build().create();

        X509Certificate x509Certificate = new X509CertificateCreator.Builder()
                .withPrivateKey(keyPair.getPrivate())
                .withSigningAlgorithm("SHA256withRSA")
                ._withSecureRandom(SecureRandom.getInstance("SHA1PRNG"))
                .withValidityStart(new Date()).withValidityEnd(Date.from(LocalDateTime.of(
                        2024, 8, 15, 00, 00).toInstant(ZoneOffset.UTC)))
                .withIssuer(subjectAndIssuer).withSubject(subjectAndIssuer).build().create(keyPair.getPublic());

        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        Certificate certificate = certFactory.generateCertificate(new ByteArrayInputStream(x509Certificate.getEncoded()));
        Assert.assertTrue(certificate instanceof X509Certificate);
        x509Certificate = (X509Certificate) certificate;
        Map<CertAttr, String> attrMap = JCryptoUtil.parseX509Name(x509Certificate.getSubjectX500Principal().getName());
        assertEquals(subjectAndIssuer, attrMap);
    }
}
