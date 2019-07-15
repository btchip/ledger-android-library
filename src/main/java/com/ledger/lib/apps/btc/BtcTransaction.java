package com.ledger.lib.apps.btc;

import com.ledger.lib.LedgerException;

/**
 * \brief Internal representation of a Bitcoin raw transaction
 */
public class BtcTransaction {

  private BtcTransaction() {    
  }

  /**
   * Create the object from a raw serialized Bitcoin Transaction
   * @param rawTransaction raw serialized Bitcoin Transaction to parse
   * @throw LedgerException if the transaction format is not correct
   */
  public static BtcTransaction createFromRaw(byte[] rawTransaction) throws LedgerException {
    return null;
  }

  /**
   * Serialize a Bitcoin Transaction
   */
  public byte[] serialize() {
    return null;    
  }

}
