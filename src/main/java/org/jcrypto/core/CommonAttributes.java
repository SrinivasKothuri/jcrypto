package org.jcrypto.core;

import java.security.SecureRandom;

public class CommonAttributes {

    protected String fProvider;
    protected SecureRandom fSecureRandom;

    public static class CommonBuilder {
        protected String fProvider;
        protected SecureRandom fSecureRandom;

        public CommonBuilder withProvider(String provider) {
            fProvider = provider;
            return this;
        }

        public CommonBuilder withSecureRandom(SecureRandom random) {
            fSecureRandom = random;
            return this;
        }
    }
}
