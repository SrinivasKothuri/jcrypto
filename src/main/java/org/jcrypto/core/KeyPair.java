package org.jcrypto.core;

import org.apache.commons.lang3.StringUtils;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

public class KeyPair extends CommonAttributes {
    private final int fKeySize;
    private final String fAlgorithm;

    public KeyPair(String algorithm, String provider, int fKeySize, SecureRandom fSecureRandom) {
        this.fKeySize = fKeySize;
        this.fSecureRandom = fSecureRandom;
        this.fAlgorithm = algorithm;
        this.fProvider = provider;
    }

    public java.security.KeyPair generate() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyGen;
        if (StringUtils.isBlank(fProvider))
            keyGen = KeyPairGenerator.getInstance(fAlgorithm);
        else
            keyGen = KeyPairGenerator.getInstance(fAlgorithm, fProvider);

        if (fKeySize != 0) {
            if (fSecureRandom != null)
                keyGen.initialize(fKeySize, fSecureRandom);
            else
                keyGen.initialize(fKeySize);
        }
        return keyGen.generateKeyPair();
    }

    public static class Builder extends CommonBuilder {
        private int fKeySize;
        private String fAlgorithm;

        public Builder withKeySize(int keySize) {
            fKeySize = keySize;
            return this;
        }

        public Builder withAlgorithm(String algorithm) {
            fAlgorithm = algorithm;
            return this;
        }

        public KeyPair generate() {
            checkDefaults();
            return new KeyPair(fAlgorithm, fProvider, fKeySize, fSecureRandom);
        }

        private void checkDefaults() {
            if (StringUtils.isBlank(fAlgorithm))
                throw new IllegalArgumentException("Algorithm should be specified to generate Keys");
        }
    }
}
