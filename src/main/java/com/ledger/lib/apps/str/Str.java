package com.ledger.lib.apps.xrp;

import com.ledger.lib.LedgerException;
import com.ledger.lib.transport.LedgerDevice;
import com.ledger.lib.apps.LedgerApplication;
import com.ledger.lib.apps.common.WalletAddress;
import com.ledger.lib.apps.common.ECDSADeviceSignature;

/**
 * \brief Communication with the device Stellar application
 */
public class Str extends LedgerApplication {

  /**
   * Constructor
   * @param device device to use
   */
  public Str(LedgerDevice device) {
    super(device);
  }

  /**
   * Get information about a wallet address
   * @param bip32Path BIP 32 path to derive
   * @param verify true if the address shall be prompted to the user for verification
   * @return information about the address
   */
  public WalletAddress getWalletAddress(String bip32Path, boolean verify) throws LedgerException {
    return null;
  }  

  /**
   * Sign a Stellar transaction
   * @param bip32Path BIP 32 path to derive
   * @param rawTranasction serialized transaction to sign
   * @param curveAlgorithm curve algorithm to use
   * @return ECDSA signature of the transaction
   */
  public ECDSADeviceSignature signTransaction(String bip32Path, byte[] rawTransaction) throws LedgerException {
    return null;
  }

}
