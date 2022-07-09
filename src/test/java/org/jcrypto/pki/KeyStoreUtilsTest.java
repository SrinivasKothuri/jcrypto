package org.jcrypto.pki;

import org.junit.Test;

public class KeyStoreUtilsTest {

	@Test
	public void testKeyStoreUpdate() throws Exception {
		String ks = "/Library/Java/JavaVirtualMachines/amazon-corretto-8.jdk/Contents/Home/jre/lib/security/cacerts";
		System.out.println(KeyStoreUtils.exploreKeyStore(ks, "changeit".toCharArray(), KeyStoreUtils.Type.JKS));
	}
}
