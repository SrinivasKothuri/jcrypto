package org.jcrypto.pki;

import com.google.common.collect.ImmutableMap;
import org.jcrypto.util.JCryptoUtil;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Map;

public class KeyStoreUtils {

	public enum Type {
		JKS
	}

	public static void storeKey(String keyStorePath, char[] password, Type type, String aliasName,
								PrivateKey privateKey, Certificate[] certificateChain)
			throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException {
		KeyStore keyStore = init(keyStorePath, password, type);
		KeyStore.PrivateKeyEntry privateKeyEntry = new KeyStore.PrivateKeyEntry(privateKey, certificateChain);
		keyStore.setEntry(aliasName, privateKeyEntry, new KeyStore.PasswordProtection(password));
		keyStore.store(new FileOutputStream(keyStorePath), password);
	}

	private static KeyStore init(String keyStorePath, char[] password, Type type) throws KeyStoreException,
			CertificateException, IOException, NoSuchAlgorithmException {
		KeyStore keyStore = KeyStore.getInstance(type.toString());
		File ksFile = new File(keyStorePath);
		if (!ksFile.exists())
			keyStore.load(null, null);
		else {
			keyStore.load(new FileInputStream(ksFile), password);
		}
		return keyStore;
	}

	public static void storeCertificate(String keyStorePath, char[] password, Type type, String aliasName,
										Certificate certificate)
			throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException {
		KeyStore keyStore = init(keyStorePath, password, type);
		keyStore.setCertificateEntry(aliasName, certificate);
		keyStore.store(new FileOutputStream(keyStorePath), password);
	}
}
