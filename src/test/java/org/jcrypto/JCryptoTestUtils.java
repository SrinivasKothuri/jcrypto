package org.jcrypto;

import org.joda.time.MutableDateTime;

import java.util.Date;

public class JCryptoTestUtils {
	public static Date daysFrom(Date startDate, int days) {
		MutableDateTime dateTime = new MutableDateTime(startDate);
		dateTime.addDays(days);
		return dateTime.toDate();
	}

	public static Date daysFromNow(int days) {
		MutableDateTime dateTime = new MutableDateTime();
		dateTime.addDays(days);
		return dateTime.toDate();
	}
}
