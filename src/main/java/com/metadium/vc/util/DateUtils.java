package com.metadium.vc.util;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

/**
 * Date convert utility
 * @author mansud
 *
 */
public class DateUtils {
	private static final String formatRFC3339UTC = "yyyy-MM-dd'T'HH:mm:ss'Z'";
	
	public static SimpleDateFormat getDateFormatRFC3339UTC() {
		SimpleDateFormat dateFormatRFC3339UTC = new SimpleDateFormat(formatRFC3339UTC);
		dateFormatRFC3339UTC.setTimeZone(TimeZone.getTimeZone("UTC"));
		
		return dateFormatRFC3339UTC;
	}
	
	/**
	 * Convert from Date to rfc3339
	 * @param date
	 * @return
	 */
	public static String toRFC3339UTC(Date date) {
		return getDateFormatRFC3339UTC().format(date);
	}
	
	/**
	 * Convert from rfc3339 to Date
	 * @param str
	 * @return
	 */
	public static Date fromRFC3339UTC(String str) {
		try {
			return getDateFormatRFC3339UTC().parse(str);
		}
		catch (ParseException e) {
			return null;
		}
	}

}
