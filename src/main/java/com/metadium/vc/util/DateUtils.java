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
	private static final SimpleDateFormat dateFormatRFC3339UTC = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
	static {
		dateFormatRFC3339UTC.setTimeZone(TimeZone.getTimeZone("UTC"));
	}
	
	/**
	 * Convert from Date to rfc3339
	 * @param date
	 * @return
	 */
	public static String toRFC3339UTC(Date date) {
		return dateFormatRFC3339UTC.format(date);
	}
	
	/**
	 * Convert from rfc3339 to Date
	 * @param str
	 * @return
	 */
	public static Date fromRFC3339UTC(String str) {
		try {
			return dateFormatRFC3339UTC.parse(str);
		}
		catch (ParseException e) {
			return null;
		}
	}

}
