package org.jcrypto.pki;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.jcrypto.util.JCryptoUtil;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Base64;

import static org.jcrypto.util.JCryptoUtil.KeyFormat.DER;

public class KeyPairCreator extends CommonAttributes {
    private final int fKeySize;
    private final String fAlgorithm;

    private KeyPairCreator(String algorithm, String provider, int fKeySize, SecureRandom secureRandom) {
        super(provider, secureRandom);
        this.fKeySize = fKeySize;
        this.fAlgorithm = algorithm;
    }

    public KeyPair create() throws NoSuchAlgorithmException, NoSuchProviderException {
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

    public static class Builder extends CommonAttributes.Builder {
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

        public KeyPairCreator build() {
            checkDefaults();
            return new KeyPairCreator(fAlgorithm, fProvider, fKeySize, fSecureRandom);
        }

        @Override
        protected void checkDefaults() {
            if (StringUtils.isBlank(fAlgorithm))
                throw new IllegalArgumentException("Algorithm is not be specified to generate Keys");
        }
    }
}
