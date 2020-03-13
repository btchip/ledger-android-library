package com.ledger.lib.apps.trx;

import com.ledger.lib.LedgerException;

/**
 * \brief Exception returned when Custom Contracts are not enabled for the TRX application
 */
public class CustomContractNotEnabledException extends LedgerException {

  public CustomContractNotEnabledException() {
    super(LedgerException.ExceptionReason.APPLICATION_ERROR, "Custom contract setting not enabled");
  }

}
