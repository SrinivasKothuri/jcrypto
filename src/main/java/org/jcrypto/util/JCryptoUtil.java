package org.jcrypto.util;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.EnumUtils;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class JCryptoUtil {
    public static enum CertAttr {
        CN(0x01, BCStyle.CN, "Common Name"), O(0x02, BCStyle.O, "Organization"),
        OU(0x04, BCStyle.OU, "Organization Unit"), C(0x08, BCStyle.C, "Country"),
        L(0x10, BCStyle.L, "Locality"), ST(0x20, BCStyle.ST, "State or Province"),
        Email(0x40, BCStyle.EmailAddress, "Email");

        private final int fCode;

        private final ASN1ObjectIdentifier fBCCode;
        private final String fDefaultName;

        CertAttr(int code, ASN1ObjectIdentifier bCCode, String defaultName) {
            fCode = code;
            fBCCode = bCCode;
            fDefaultName = defaultName;
        }

        public int getCode() {
            return fCode;
        }

        public String getDefaultName() {
            return fDefaultName;
        }
    }

    public static X500Name createNameFromMap(Map<CertAttr, String> certAttributes) {
        X500NameBuilder issuerBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        certAttributes.keySet().stream().forEach(
                key -> issuerBuilder.addRDN(key.fBCCode, certAttributes.get(key)));
        return issuerBuilder.build();
    }

    public static Map<CertAttr, String> parseX509Name(String x509Name) {
        String[] names = StringUtils.split(x509Name, ",");
        if (ArrayUtils.isEmpty(names))
            return Collections.EMPTY_MAP;

        Map<CertAttr, String> attrsMap = new HashMap<>();
        for (String name: names) {
            String[] nameSplit = StringUtils.split(name, '=');
            if (ArrayUtils.getLength(nameSplit) < 2 ||
                    !EnumUtils.isValidEnumIgnoreCase(CertAttr.class, nameSplit[0]) ||
                    StringUtils.isBlank(nameSplit[1]))
                continue;
            attrsMap.put(CertAttr.valueOf(nameSplit[0].trim().toUpperCase()), nameSplit[1].trim());
        }
        return attrsMap;
    }

    public static String getLocalizedName(CertAttr certAttr) {
        //TODO: handle localization
        return certAttr.getDefaultName();
    }
}
