package org.jcrypto.util;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;

import java.util.Map;

public class JCryptoUtil {
    public static X500Name createNameFromMap(Map<Object, String> certAttributes) {
        X500NameBuilder issuerBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        certAttributes.keySet().stream().forEach(
                key -> issuerBuilder.addRDN((ASN1ObjectIdentifier) key, certAttributes.get(key)));
        return issuerBuilder.build();
    }
}
