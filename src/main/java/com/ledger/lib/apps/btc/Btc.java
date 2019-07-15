package com.ledger.lib.apps.btc;

import java.util.List;
import java.math.BigInteger;

import com.ledger.lib.LedgerException;
import com.ledger.lib.transport.LedgerDevice;
import com.ledger.lib.apps.LedgerApplication;
import com.ledger.lib.apps.common.WalletAddress;
import com.ledger.lib.apps.common.ECDSADeviceSignature;

/**
 * \brief Communication with the device BTC application, and all forks based on the BTC application
 */
public class Btc extends LedgerApplication {


  /** \brief Information about an Unspent Transaction Output to be included in a transaction */
  public class UTXO {
    /** Get the transaction from which the UTXO is originated */
    public BtcTransaction getParentTransaction() {
      return null;      
    }

    /** Get the index of the UTXO in the transaction */
    public long getOutputIndex() {      
      return 0;
    }

    /** Get the optional redeem script when consuming a Segregated Witness input */
    public byte[] getRedeemScript() {      
      return null;
    }

    /** Get the optional sequence number associated to this UTXO in the transaction Iwhen using Replace By Fee)*/
    public long getSequence() {
      return 0;      
    }


  }

  /** \brief Type of Bitcoin addresses */
  public enum AddressFormat {    
    LEGACY, /** Legacy P2PKH address format */
    P2SH, /** Segwit P2WPKH over P2SH address format */
    BECH32 /** Native Segwit P2WPKH address format using Bech32 encoding */
  };

  /** \brief SigHashType of a Bitcoin transaction */
  public enum SigHashType {
    SIGHASH_ALL,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
    SIGHASH_ANYONECANPAY,
  };

  /** \brief Modifiers used for signing with a specific Bitcoin fork */
  public enum BtcModifiers {
    ABC, /** Signing for a coin using Bitcoin Cash FORK_ID mechanism */
    GOLD, /** Signing for Bitcoin Gold */
    BIP143 /** Signing for a coin using BIP 143 */
  }

  /**
   * Constructor
   * @param device device to use
   */
  public Btc(LedgerDevice device) {
    super(device);
  }

  /**
   * Get information about a wallet address
   * @param bip32Path BIP 32 path to derive
   * @param verify true if the address shall be prompted to the user for verification
   * @param format format of the address
   * @return information about the address
   */
  public WalletAddress getWalletAddress(String bip32Path, boolean verify, AddressFormat format) throws LedgerException {
    return null;
  }  

  /**
   * Sign a P2PKH transaction
   * @param utxos list of UTXO and associated information to sign
   * @param associatedKeysets BIP 32 path of each private key associated to each UTXO
   * @param changePath optional BIP 32 path of the public key used to compute the change address
   * @param outputScript serialized outputs of the transaction to sign
   * @param lockTime optional Locktime of the transaction to sign
   * @param sigHashType Sighashtype of the transaction to sign (only SIGHASH_ALL is supported)
   * @param segwit set to true if the inputs are originating from Segregated Witness addresses
   * @param timestamp optional timestamp if necessary for the cryptocurrency being used
   * @param options optional signing options related to the cryptocurrency being used
   * @param expiryHeight optional expiry height if signing a ZCash transaction
   * @return the signed transasction ready to be broadcast
   */
  public BtcTransaction signP2PKHTransaction(List<UTXO> utxos, List<String> associatedKeysets, String changePath, byte[] outputScript, long lockTime, SigHashType sigHashType, boolean segwit, BigInteger timestamp, BtcModifiers options, BigInteger expiryHeight) throws LedgerException {
    return null;
  }

  /**
   * Sign a message according to the Bitcoin Signature format
   * @param bip32Path BIP 32 path to derive
   * @param message message to sign
   * @return ECDSA signature of the message
   */
  public ECDSADeviceSignature signMessage(String bip32Path, byte[] message) throws LedgerException {
    return null;
  }
}
