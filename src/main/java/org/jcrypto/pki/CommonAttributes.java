package org.jcrypto.pki;

import org.jcrypto.annotations.JCryptoAttr;

import java.security.SecureRandom;

public class CommonAttributes {

    @JCryptoAttr
    protected String fProvider;
    @JCryptoAttr
    protected SecureRandom fSecureRandom;

    public CommonAttributes(String provider, SecureRandom secureRandom) {
        fProvider = provider;
        fSecureRandom = secureRandom;
    }

    public abstract static class Builder {
        protected String fProvider;
        protected SecureRandom fSecureRandom;

        public Builder withProvider(String provider) {
            fProvider = provider;
            return this;
        }

        public Builder withSecureRandom(SecureRandom random) {
            fSecureRandom = random;
            return this;
        }

        protected abstract void checkDefaults();
    }
}
