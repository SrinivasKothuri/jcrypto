package org.jcrypto.pki;

import java.security.SecureRandom;

public class CommonAttributes {

    protected String fProvider;
    protected SecureRandom fSecureRandom;

    public CommonAttributes(String provider, SecureRandom secureRandom) {
        fProvider = provider;
        fSecureRandom = secureRandom;
    }

    public abstract static class Builder<T> {
        protected String fProvider;
        protected SecureRandom fSecureRandom;

        public T _withProvider(String provider) {
            fProvider = provider;
            return (T) this;
        }

        public T _withSecureRandom(SecureRandom random) {
            fSecureRandom = random;
            return (T) this;
        }

        protected abstract void checkDefaults();
    }
}
