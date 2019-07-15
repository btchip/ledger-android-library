package com.ledger.lib.utils;

import java.io.ByteArrayOutputStream;

import com.ledger.lib.LedgerException;

/**
 * Helper for BIP32 serialization
 */
public class BIP32Helper {

	public static byte[] splitPath(String path) throws LedgerException {
		if (path.length() == 0) {
			return new byte[] { 0 };
		}		
		String elements[] = path.split("/");
		if (elements.length > 10) {
			throw new LedgerException(LedgerException.ExceptionReason.INTERNAL_ERROR, "Path too long");
		}
		ByteArrayOutputStream result = new ByteArrayOutputStream();
		result.write((byte)elements.length);
		for (String element : elements) {
			long elementValue;
			int hardenedIndex = element.indexOf('\'');
			if (hardenedIndex > 0) {
				elementValue = Long.parseLong(element.substring(0, hardenedIndex));
				elementValue |= 0x80000000;
			}
			else {
				elementValue = Long.parseLong(element);
			}
			SerializeHelper.writeUint32BE(result, elementValue);
		}
		return result.toByteArray();
	}	

}
