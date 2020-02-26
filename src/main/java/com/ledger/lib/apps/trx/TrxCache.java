package com.ledger.lib.apps.trx;

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
 * Cache Tron signed information
 */
public class TrxCache {

	private static HashMap<Long, byte[]> cacheTrc10 = new HashMap<Long, byte[]>();
	private static HashMap<Long, byte[]> cacheExchanges = new HashMap<Long, byte[]>();

	/**
	 * Check if the Tron signed information cache has been provisioned
	 * @return true if the cache has been provisioned
	 */
	public static boolean isProvisioned() {
		return cacheTrc10.size() != 0;
	}

	/**
	 * Load a cache following a provided provisioning blob
	 * @param cache cache to load
	 * @param blob provisioning blob
	 */
	private static void loadCache(HashMap<Long, byte[]> cache, byte[] blob) throws LedgerException {
		int offset = 0;
		cache.clear();
		while (offset != blob.length) {
			long id = SerializeHelper.readUint32BE(blob, offset);
			int itemSize = (int)SerializeHelper.readUint32BE(blob, offset + 4);
			cache.put(id, Arrays.copyOfRange(blob, offset + 4 + 4, offset + 4 + 4 + itemSize));
			offset += 4 + 4 + itemSize;
		}
	}

	/**
	 * Load the TRC 10 cache following a provided provisioning blob
	 * @param blob provisioning blob
	 */
	public static void loadTrc10Cache(byte[] blob) throws LedgerException {
		loadCache(cacheTrc10, blob);
	}

	/**
	 * Load the Exchanges cache following a provided provisioning blob
	 * @param blob provisioning blob
	 */
	public static void loadExchangesCache(byte[] blob) throws LedgerException {
		loadCache(cacheExchanges, blob);
	}

	private static byte[] readResource(Context context, int id) {
		try {
			BufferedInputStream is = new BufferedInputStream(context.getResources().openRawResource(id));
			byte[] data = new byte[is.available()];
			int offset = 0;
			while (offset != data.length) {
				int dataRead = is.read(data, offset, data.length - offset);
				offset += dataRead;
			}
			return data;
		}
		catch(IOException e) {
			throw new LedgerException(LedgerException.ExceptionReason.INTERNAL_ERROR, e);
		}		
	}

	/**
	 * Load the caches following the internal provisioning blob
	 * @param context application context
	 */
	public static void loadCacheInternal(Context context) throws LedgerException {
		loadTrc10Cache(readResource(context, R.raw.trc10));
		loadExchangesCache(readResource(context, R.raw.tronexchanges));
	}

	/**
	 * Look up a given TRC 10 ID in the cache
	 * @param id id to look up
	 * @return associated blob or null if not present
	 */
	public static byte[] lookupTrc10(Long id) {
		return cacheTrc10.get(id);
	}

	/**
	 * Look up a given Exchange ID in the cache
	 * @param id id to look up
	 * @return associated blob or null if not present
	 */
	public static byte[] lookupExchange(Long id) {
		return cacheExchanges.get(id);
	}

}
