package com.ledger.lib.utils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import com.ledger.lib.LedgerException;

/**
 * Helper for serializing and deserializing Bitcoin encoded variable integers
 */
public class VarintUtils {

	/**
	 * Read a variable integer
	 * @param in buffer to read the variable integer from
	 * @param offset offset to the string
	 * @param length length of the string
	 * @return variable integer
	 */
	public static long read(ByteArrayInputStream in) throws LedgerException {
		long result = 0;
		int val1 = (int)(in.read() & 0xff);
		if (val1 < 0xfd) {
			result = val1;
		}
		else
		if (val1 == 0xfd) {
			result |= (int)(in.read() & 0xff);
			result |= (((int)in.read() & 0xff) << 8);
		}
		else
		if (val1 == 0xfe) {
			result |= (int)(in.read() & 0xff);
			result |= (((int)in.read() & 0xff) << 8);
			result |= (((int)in.read() & 0xff) << 16);
			result |= (((int)in.read() & 0xff) << 24);
		}
		else {
			 throw new LedgerException(LedgerException.ExceptionReason.INVALID_PARAMETER, "Unsupported varint encoding");
		}
		return result;
	}

	/**
	 * Write a variable integer
	 * @param in buffer to write the variable integer to
	 * @param value integer value to encode
	 */	
	public static void write(ByteArrayOutputStream buffer, long value) {
		if (value < 0xfd) {
			buffer.write((byte)value);
		}
		else
		if (value <= 0xffff) {
			buffer.write(0xfd);
			buffer.write((byte)(value & 0xff));
			buffer.write((byte)((value >> 8) & 0xff));			
		}
		else {
			buffer.write(0xfe);
			buffer.write((byte)(value & 0xff));
			buffer.write((byte)((value >> 8) & 0xff));
			buffer.write((byte)((value >> 16) & 0xff));
			buffer.write((byte)((value >> 24) & 0xff));
		}
	}	
}
