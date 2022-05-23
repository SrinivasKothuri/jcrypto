package org.jcrypto.core;

public class Certificate extends CommonAttributes {
    public static class Builder {
        private String fKeyType;
        private String fSigningAlgorithm;
        private String fProvider;
        private String fSecureRandom;
    }
}
