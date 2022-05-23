package org.jcrypto.pki;

import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

public class SelfSignedCertificateCreator extends CommonAttributes {

    private static final long SECONDS_IN_YEAR = 31536000;

    private String fKeyType;
    private String fSigningAlgorithm;
    private X500Name fX500Name;
    private Date fValidityStart;
    private long fValidityDuration;
    private int fKeySize = -1;

    private SelfSignedCertificateCreator(String provider, SecureRandom secureRandom, String keyType,
                                         String signingAlgorithm, X500Name x500Name, Date validityStart,
                                         long validityDuration, int keySize) {
        super(provider, secureRandom);
        fKeyType = keyType;
        fSigningAlgorithm = signingAlgorithm;
        fX500Name = x500Name;
        fValidityStart = validityStart;
        fValidityDuration = validityDuration;
        fKeySize = keySize;
    }

    public X509Certificate create() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException,
            CertificateException, SignatureException {

        CertAndKeyGen certAndKeyGen;
        if (fProvider == null)
            certAndKeyGen = new CertAndKeyGen(fKeyType, fSigningAlgorithm);
        else
            certAndKeyGen = new CertAndKeyGen(fKeyType, fSigningAlgorithm, fProvider);

        if (fSecureRandom != null)
            certAndKeyGen.setRandom(fSecureRandom);

        if (fKeySize > 0)
            certAndKeyGen.generate(fKeySize);

        return certAndKeyGen.getSelfCertificate(fX500Name, fValidityStart, fValidityDuration);
    }

    public static class Builder extends CommonAttributes.Builder {
        private String fKeyType;
        private int fKeySize = -1;
        private String fSigningAlgorithm;
        private X500Name fX500Name;
        private Date fValidityStart = new Date();
        private long fValidityDuration = SECONDS_IN_YEAR;


        public Builder withKeyType(String keyType) {
            fKeyType = keyType;
            return this;
        }

        public Builder withSigningAlgorithm(String signingAlgorithm) {
            fSigningAlgorithm = signingAlgorithm;
            return this;
        }

        public Builder withKeySize(int keySize) {
            fKeySize = keySize;
            return this;
        }

        public Builder withX500Name(X500Name x500name) {
            fX500Name = x500name;
            return this;
        }

        public Builder withValidityStart(Date validityStart) {
            fValidityStart = validityStart;
            return this;
        }

        public SelfSignedCertificateCreator build() {
            return new SelfSignedCertificateCreator(fProvider, fSecureRandom, fKeyType, fSigningAlgorithm,
                    fX500Name, fValidityStart, fValidityDuration, fKeySize);
        }

        @Override
        protected void checkDefaults() {
            if (fKeyType == null)
                throw new IllegalArgumentException("KeyType is not specified to create Certificate");
            if (fSigningAlgorithm == null)
                throw new IllegalArgumentException("Signing Algorithm is not specified to create Certificate");
            if (fX500Name == null)
                throw new IllegalArgumentException("One or more X500Name are not specified to create Certificate");
        }
    }
}
