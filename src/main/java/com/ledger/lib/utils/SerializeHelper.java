package com.ledger.lib.utils;

import java.util.Arrays;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.ByteBuffer;

import com.ledger.lib.apps.common.WalletAddress;

/**
 * Helper for serialization primitives
 */
public class SerializeHelper {

	/**
	 * Read an ASCII encoded string from a binary content
	 * @param buffer ASCII encoded string
	 * @param offset offset to the string
	 * @param length length of the string
	 * @return decoded string
	 */
	public static String readString(byte[] buffer, int offset, int length) {
		return StandardCharsets.US_ASCII.decode(ByteBuffer.wrap(Arrays.copyOfRange(buffer, offset, offset + length))).toString();		
	}

	/**
	 * Read a big endian encoded uint32 value from a buffer
	 * @param buffer buffer to read from
	 * @param offset offset to read from in the bufffer
	 * @return uint32 value
	 */
	public static long readUint32BE(byte[] buffer, int offset) {
		return ((buffer[offset] & 0xff) << 24) | ((buffer[offset + 1] & 0xff) << 16) | ((buffer[offset + 2] & 0xff) << 8) | (buffer[offset + 3] & 0xff);
	}

	/**
	 * Write a big endian encoded uint32 value into a buffer
	 * @param buffer buffer to write to
	 * @param value value to write
	 */
	public static void writeUint32BE(ByteArrayOutputStream buffer, long value) {
		buffer.write((byte)((value >> 24) & 0xff));
		buffer.write((byte)((value >> 16) & 0xff));
		buffer.write((byte)((value >> 8) & 0xff));
		buffer.write((byte)(value & 0xff));		
	}

	/**
	 * Write a little endian encoded uint32 value into a buffer
	 * @param buffer buffer to write to
	 * @param value value to write
	 */
	public static void writeUint32LE(ByteArrayOutputStream buffer, long value) {
		buffer.write((byte)(value & 0xff));		
		buffer.write((byte)((value >> 8) & 0xff));
		buffer.write((byte)((value >> 16) & 0xff));
		buffer.write((byte)((value >> 24) & 0xff));				
	}
	
	/**
	 * Write a little endian encoded uint64 value into a buffer
	 * @param buffer buffer to write to
	 * @param value value to write
	 */	
	public static void writeUint64LE(ByteArrayOutputStream buffer, long value) {
		buffer.write((byte)(value & 0xff));		
		buffer.write((byte)((value >> 8) & 0xff));
		buffer.write((byte)((value >> 16) & 0xff));
		buffer.write((byte)((value >> 24) & 0xff));				
		buffer.write((byte)((value >> 32) & 0xff));
		buffer.write((byte)((value >> 40) & 0xff));
		buffer.write((byte)((value >> 48) & 0xff));
		buffer.write((byte)((value >> 56) & 0xff));		
	}

	/**
	 * Write a big endian encoded uint64 value into a buffer
	 * @param buffer buffer to write to
	 * @param value value to write
	 */		
	public static void writeUint64BE(ByteArrayOutputStream buffer, long value) {
		buffer.write((byte)((value >> 56) & 0xff));
		buffer.write((byte)((value >> 48) & 0xff));
		buffer.write((byte)((value >> 40) & 0xff));
		buffer.write((byte)((value >> 32) & 0xff));
		buffer.write((byte)((value >> 24) & 0xff));
		buffer.write((byte)((value >> 16) & 0xff));
		buffer.write((byte)((value >> 8) & 0xff));
		buffer.write((byte)(value & 0xff));						
	}
	
	/**
	 * Write a byte array value into a buffer
	 * @param buffer buffer to write to
	 * @param value value to write
	 */
	public static void writeBuffer(ByteArrayOutputStream buffer, byte[] value) {
		buffer.write(value, 0, value.length);
	}	

	/**
	 * Convert an ASCII string into a byte array
	 * @param data String to convert
	 * @return encoded string
	 */
	public static byte[] stringToByteArray(String data) {
		return StandardCharsets.US_ASCII.encode(data).array();
	}

	/**
	 * Unserialize wallet address information encdoded using the common application encoding
	 * @param buffer buffer containing the wallet address information
	 * @return wallet address information
	 */
	public static WalletAddress readWalletAddress(byte[] buffer) {
		byte[] chainCode = null;
		int offset = 0;
		int publicKeyLength = (buffer[offset++] & 0xff);
		byte[] publicKey = Arrays.copyOfRange(buffer, offset, offset + publicKeyLength);
		offset += publicKeyLength;
		int coinAddressLength = (buffer[offset++] & 0xff);
		String coinAddress = readString(buffer, offset, coinAddressLength);
		offset += coinAddressLength;
		if ((offset + 32) <= buffer.length) {
			chainCode = Arrays.copyOfRange(buffer, offset, offset + 32);
		}
		return new WalletAddress(publicKey, coinAddress, chainCode);
	}

}
