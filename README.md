# jCrypto (Work in progress)
jCrypto provides a more readable Java API in Builder-pattern to create/validate/update PKI and Symmetric keys and KeyStores. jCrypto aims to provide the keytool/openssl's command line options to be provided in a programatic way. It doesn't rely on the `com.sun.*` classes that are JVM specific and limited visibility, instead it relys on BouncyCastle PKIX utilities to generate X509 certtificates. 

### Example:
#### Create Key Pair:
```java
KeyPair keyPair = new KeyPairCreator.Builder()
  .withKeySize(2048)
  .withAlgorithm("RSA")
  ._withProvider("SUN")
  ._withSecureRandom(SecureRandom.getInstance("SHA1PRNG"))
  .build().create();
```
where some of the builder methods prefixed with `_` to indicate optional attributes.

#### Create self-signed X509 Certificate:
```java
Map<CertAttr, String> subjectAndIssuer = ImmutableMap.of(CertAttr.CN, "skothuri.home.com", CertAttr.C, "IN", CertAttr.O, "Home");

X509Certificate x509Certificate = new X509CertificateCreator.Builder()
  .withPrivateKey(keyPair.getPrivate())
  .withSigningAlgorithm("SHA256withRSA")
  .withValidityStart(startDate)
  .withValidityEnd(JCryptoUtil.daysFrom(startDate, 365))
  .withIssuer(subjectAndIssuer)
  .withSubject(subjectAndIssuer).build().create(keyPair.getPublic());
```

#### Signing InoutStream
```java
String testData = "0123456789";

KeyPair keyPair = new KeyPairCreator.Builder().withKeySize(2048).withAlgorithm("RSA").build().create();
byte[] md5withRSAS = new Signer().algorithm("MD5withRSA").privateKey(keyPair.getPrivate())
			.sign(new ByteArrayInputStream(testData.getBytes(StandardCharsets.UTF_8)));
```

#### Verifying the Signature
```java
assertTrue(new Verifier().algorithm("MD5withRSA").publicKey(keyPair.getPublic())
			.verify(new ByteArrayInputStream(testData.getBytes(StandardCharsets.UTF_8)), md5withRSAS));
```
