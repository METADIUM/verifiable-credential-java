package com.metadium.vc.util;

import java.math.BigInteger;

public class Numeric {
	public static byte[] toBytesPadded(BigInteger value, int length) {
		byte[] result = new byte[length];
		byte[] bytes = value.toByteArray();
		int bytesLength;
		byte srcOffset;
		if (bytes[0] == 0) {
			bytesLength = bytes.length - 1;
			srcOffset = 1;
		} else {
			bytesLength = bytes.length;
			srcOffset = 0;
		}

		if (bytesLength > length) {
			throw new RuntimeException("Input is too large to put in byte array of size " + length);
		} else {
			int destOffset = length - bytesLength;
			System.arraycopy(bytes, srcOffset, result, destOffset, bytesLength);
			return result;
		}
	}
}
