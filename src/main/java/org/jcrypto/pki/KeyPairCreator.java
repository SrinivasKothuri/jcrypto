package org.jcrypto.pki;

import org.apache.commons.lang3.StringUtils;
import org.jcrypto.util.JCryptoUtil;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

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

    public void store(String targetDir, String pubFileName, JCryptoUtil.KeyFormat pubFormat, String privFileName,
                      JCryptoUtil.KeyFormat privFormat)
            throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
        KeyPair keyPair = create();

        byte[] content = keyPair.getPrivate().getEncoded();
        JCryptoUtil.storePrivateKey(privFormat, targetDir, privFileName, content);

        content = keyPair.getPrivate().getEncoded();
        JCryptoUtil.storePublicKey(pubFormat, targetDir, pubFileName, content);
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
            if (fKeySize <= 0)
                throw new IllegalArgumentException("Invalid key size is specified to generate Keys");
            if (StringUtils.isBlank(fAlgorithm))
                throw new IllegalArgumentException("Algorithm is not be specified to generate Keys");
        }
    }
}
