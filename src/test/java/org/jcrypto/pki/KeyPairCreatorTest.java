package org.jcrypto.pki;

import org.junit.Test;

import java.security.KeyPair;

public class KeyPairCreatorTest {

    @Test
    public void testPrivateKey() throws Exception {
        KeyPair rsa = new KeyPairCreator.Builder().withAlgorithm("RSA").withKeySize(2048).build().create();
        System.out.println(rsa.getPrivate().getAlgorithm());
        System.out.println(rsa.getPrivate().getFormat());
    }
}
