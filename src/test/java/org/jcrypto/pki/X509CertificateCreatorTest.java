package org.jcrypto.pki;

import com.google.common.collect.ImmutableMap;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.junit.Test;

import java.io.FileOutputStream;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Date;

public class X509CertificateCreatorTest {
    @Test
    public void testSelfSignedX509CertificateCreation() throws Exception {
        ImmutableMap<Object, String> subjectAndIssuer =
                ImmutableMap.of(BCStyle.CN, "skothuri.home.com", BCStyle.C, "IN", BCStyle.O, "Home");
        X509Certificate x509Certificate = new X509CertificateCreator.Builder().withKeySize(2048)
                .withKeyType("RSA").withSigningAlgorithm("SHA256withRSA")
                .withValidityStart(new Date()).withValidityEnd(Date.from(LocalDateTime.of(2024, 8, 15, 00, 00).toInstant(ZoneOffset.UTC)))
                .withIssuer(subjectAndIssuer).withSubject(subjectAndIssuer).build().create();
        IOUtils.write(x509Certificate.getTBSCertificate(), new FileOutputStream("cert.der"));
    }
}
