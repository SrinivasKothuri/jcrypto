package org.jcrypto.pki;

import com.google.common.collect.ImmutableMap;
import org.jcrypto.util.JCryptoUtil.CertAttr;
import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Date;

public class X509CertificateCreatorTest {
    @Test
    public void testSelfSignedX509CertificateCreation() throws Exception {
        ImmutableMap<CertAttr, String> subjectAndIssuer =
                ImmutableMap.of(CertAttr.CN, "skothuri.home.com", CertAttr.C, "IN", CertAttr.O, "Home");
        X509Certificate x509Certificate = new X509CertificateCreator.Builder().withKeySize(2048)
                .withKeyType("RSA").withSigningAlgorithm("SHA256withRSA")
                .withValidityStart(new Date()).withValidityEnd(Date.from(LocalDateTime.of(
                        2024, 8, 15, 00, 00).toInstant(ZoneOffset.UTC)))
                .withIssuer(subjectAndIssuer).withSubject(subjectAndIssuer).build().create();
        //IOUtils.write(x509Certificate.getTBSCertificate(), new FileOutputStream("cert.der"));
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        Certificate certificate = certFactory.generateCertificate(new ByteArrayInputStream(x509Certificate.getEncoded()));
        Assert.assertTrue(certificate instanceof X509Certificate);
        x509Certificate = (X509Certificate) certificate;
        System.out.println(x509Certificate.getSubjectX500Principal().getName());
    }
}
