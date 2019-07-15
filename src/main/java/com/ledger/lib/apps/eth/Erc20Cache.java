package com.ledger.lib.apps.eth;

import java.util.Arrays;
import java.util.HashMap;
import java.io.IOException;
import java.io.InputStream;
import java.io.ByteArrayOutputStream;
import java.io.BufferedInputStream;

import android.content.Context;
import android.content.res.Resources;

import com.ledger.lib.utils.SerializeHelper;
import com.ledger.lib.utils.Dump;
import com.ledger.lib.LedgerException;
import com.ledger.lib.R;

/**
 * Cache Erc20 tokens information
 */
public class Erc20Cache {

	private static HashMap<String, byte[]> cache = new HashMap<String, byte[]>();

	/**
	 * Check if the ERC 20 cache has been provisioned
	 * @return true if the cache has been provisioned
	 */
	public static boolean isProvisioned() {
		return cache.size() != 0;
	}

	/**
	 * Load the cache following a provided provisioning lob
	 * @param blob provisioning blob
	 */
	public static void loadCache(byte[] blob) throws LedgerException {
		int offset = 0;
		cache.clear();
		while (offset != blob.length) {
			int itemSize = (int)SerializeHelper.readUint32BE(blob, offset);			
			offset += 4;
			int nextOffset = offset + itemSize;
			byte[] item = Arrays.copyOfRange(blob, offset, offset + itemSize);
			int tickerLength = (blob[offset++] & 0xff);
			offset += tickerLength;
			String contractAddress = Dump.dump(blob, offset, 20).toLowerCase();
			cache.put(contractAddress, item);
			offset = nextOffset;
		}
	}

	/**
	 * Load the cache following the internal provisioning blob
	 * @param context application context
	 */
	public static void loadCacheInternal(Context context) throws LedgerException {
		try {
			BufferedInputStream is = new BufferedInputStream(context.getResources().openRawResource(R.raw.erc20));
			byte[] data = new byte[is.available()];
			int offset = 0;
			while (offset != data.length) {
				int dataRead = is.read(data, offset, data.length - offset);
				offset += dataRead;
			}
			loadCache(data);
		}
		catch(IOException e) {
			throw new LedgerException(LedgerException.ExceptionReason.INTERNAL_ERROR, e);
		}
	}

	/**
	 * Look up a given contract address in the ERC 20 cache
	 * @param address address to look up
	 * @return ERC 20 associated blob or null if not present
	 */
	public static byte[] lookup(String address) {
		address = address.toLowerCase();
		if (address.startsWith("0x")) {
			address = address.substring(2);
		}
		return cache.get(address);
	}

}
