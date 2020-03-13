package com.ledger.lib.apps.trx;

import java.util.Arrays;
import java.util.Vector;
import java.io.ByteArrayOutputStream;

import com.ledger.lib.LedgerException;
import com.ledger.lib.transport.LedgerDevice;
import com.ledger.lib.apps.LedgerApplication;
import com.ledger.lib.apps.common.WalletAddress;
import com.ledger.lib.apps.common.ECDSADeviceSignature;
import com.ledger.lib.utils.SW;
import com.ledger.lib.utils.BIP32Helper;
import com.ledger.lib.utils.ApduExchange;
import com.ledger.lib.utils.SerializeHelper;

/**
 * \brief Communication with the device TRX application
 */
public class Trx extends LedgerApplication {

  /**
   * \brief Details about the TRX application
   */
  public class TrxConfiguration {

    /** Set if arbitrary contract data signing is allowed by the user */
    public static final int FLAG_DATA_ALLOWED = 0x01;
    /** Set if custom contracts are allowed */
    public static final int FLAG_CONTRACT_ALLOWED = 0x02;
    /** Set if the address is truncated */
    public static final int FLAG_TRUNCATE_ADDRESS = 0x04;
    
    private int flags;

    TrxConfiguration(byte[] response) {
      int offset = 0;      
      flags = (response[offset++] & 0xff);
      if ((response[offset] == 0) && (response[offset + 1] == 1) && (response[offset + 2] < 2)) {
        flags |= FLAG_DATA_ALLOWED;
        flags &= ~FLAG_CONTRACT_ALLOWED;
      }
      if ((response[offset] == 0) && (response[offset + 1] == 1) && (response[offset + 2] < 5)) {
        flags &= ~FLAG_TRUNCATE_ADDRESS;
      }
    }

    /** Return the application flags */
    public int getFlags() {
      return flags;
    }

    /** Convert the flags to a string */
    public String flagsToString() {
      String result = "";
      if ((flags & FLAG_DATA_ALLOWED) != 0) {
        result += "Data signing allowed,";
      }
      if ((flags & FLAG_CONTRACT_ALLOWED) != 0) {
        result += "Custom contracts allowed,";
      }
      if ((flags & FLAG_TRUNCATE_ADDRESS) != 0) {
        result += "Truncate address,";
      }
      if (result.length() == 0) {
        return result;
      }
      else {
        return result.substring(0, result.length() - 1);
      }
    }

    public String toString() {
      return flagsToString();
    }
  }

  private static final int TRX_CLA = 0xE0;
  private static final int INS_GET_PUBLIC_ADDRESS = 0x02;
  private static final int INS_SIGN_TRANSACTION = 0x04;
  private static final int INS_GET_APPLICATION_CONFIGURATION = 0x06;
  private static final int INS_SIGN_PERSONAL_MESSAGE = 0x08;
  private static final int INS_GET_ECDH_SECRET = 0x0A;

  private static final int P1_NO_DISPLAY = 0x00;
  private static final int P1_DISPLAY = 0x01;  
  private static final int P1_SINGLE = 0x10;
  private static final int P1_FIRST_BLOCK = 0x00;
  private static final int P1_NEXT_BLOCK = 0x80;
  private static final int P1_SIGNATURE_MARKER = 0xA0;
  private static final int P1_END = 0x90;
  private static final int P1_END_SIGNATURE_MARKER = 0x08;
  private static final int P2_NO_CHAINCODE = 0x00;
  private static final int P2_CHAINCODE = 0x01;

  private static final int MAX_BLOCK_SIZE = 255;

  /**
   * Constructor
   * @param device device to use
   */
  public Trx(LedgerDevice device) {
    super(device);
  }

  /**
   * Get information about a wallet address
   * @param bip32Path BIP 32 path to derive
   * @param verify true if the address shall be prompted to the user for verification
   * @return information about the address
   */
  public WalletAddress getWalletAddress(String bip32Path, boolean verify) throws LedgerException {
    byte[] convertedPath = BIP32Helper.splitPath(bip32Path);
    ApduExchange.ApduResponse response = ApduExchange.exchangeApdu(device, TRX_CLA, 
      INS_GET_PUBLIC_ADDRESS, 
      (verify ? P1_DISPLAY : P1_NO_DISPLAY),
      P2_CHAINCODE,
      convertedPath);
    response.checkSW();
    return SerializeHelper.readWalletAddress(response.getResponse());
  }  

  /** 
   * Return the application configuration
   * @return application configuration
   */
  public TrxConfiguration getConfiguration() throws LedgerException {
    ApduExchange.ApduResponse response = ApduExchange.exchangeApdu(device, TRX_CLA, INS_GET_APPLICATION_CONFIGURATION, 0, 0);
    response.checkSW();
    return new TrxConfiguration(response.getResponse());
  }  

  /**
   * Sign a Tron transaction
   * @param bip32Path BIP 32 path to derive
   * @param rawTranasction serialized transaction to sign
   * @return ECDSA signature of the transaction
   */
  public ECDSADeviceSignature signTransaction(String bip32Path, byte[] rawTransaction) throws LedgerException {
    return signInfoTransaction(bip32Path, rawTransaction, null);
  }

  /**
   * Sign a Tron transaction with external signed data provided
   * @param bip32Path BIP 32 path to derive
   * @param rawTranasction serialized transaction to sign
   * @param provisioningData list of provisioning data returned by getTrc10TokenInformation or getExchangeInformation
   * @return ECDSA signature of the transaction
   */
  public ECDSADeviceSignature signInfoTransaction(String bip32Path, byte[] rawTransaction, Vector<byte[]> provisioningData) throws LedgerException {
    byte[] convertedPath = BIP32Helper.splitPath(bip32Path);
    int offset = 0;
    ApduExchange.ApduResponse response = null;
    // Send the TX
    while (offset != rawTransaction.length) {
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      int p1;
      int maxBlockSize = (offset == 0 ? MAX_BLOCK_SIZE - convertedPath.length : MAX_BLOCK_SIZE);
      int blockSize = (offset + maxBlockSize > rawTransaction.length ? rawTransaction.length - offset : maxBlockSize);
      if (offset == 0) {
        out.write(convertedPath, 0, convertedPath.length);
      }
      out.write(Arrays.copyOfRange(rawTransaction, offset, offset + blockSize), 0, blockSize);
      if (offset == 0) {
        if (((offset + blockSize) == rawTransaction.length) && 
          ((provisioningData == null) || (provisioningData.size() == 0))) {
          p1 = P1_SINGLE;        
        }
        else {
          p1 = P1_FIRST_BLOCK;
        }
      }
      else {
        if (((offset + blockSize) == rawTransaction.length) && 
          ((provisioningData == null) || (provisioningData.size() == 0))) {
          p1 = P1_END;        
        }
        else {
          p1 = P1_NEXT_BLOCK;
        }
      }
      response = ApduExchange.exchangeApdu(device, TRX_CLA, 
        INS_SIGN_TRANSACTION, 
        p1,
        0,
        out.toByteArray());
      if (response.getSW() == SW.SW_INCORRECT_P1_P2) {
        // Most legitimate reason to receive this here
        throw new CustomContractNotEnabledException();
      }
      response.checkSW();
      offset += blockSize;
    }
    // Send the extra signature data
    if ((provisioningData != null) && (provisioningData.size() != 0)) {
      for (int i=0; i<provisioningData.size(); i++) {
        int p1;
        if (i != provisioningData.size() - 1) {
          p1 = P1_SIGNATURE_MARKER + i;
        }
        else {
          p1 = P1_SIGNATURE_MARKER | P1_END_SIGNATURE_MARKER + provisioningData.size() - 1;
        }
        response = ApduExchange.exchangeApdu(device, TRX_CLA, 
          INS_SIGN_TRANSACTION, 
          p1,
          0,
          provisioningData.get(i));
        response.checkSW();
      }
    }    
    byte[] responseData = response.getResponse();
    return new ECDSADeviceSignature((responseData[64] & 0xff), 
      Arrays.copyOfRange(responseData, 0, 0 + 32),
      Arrays.copyOfRange(responseData, 0 + 32, 0 + 32 + 32));    
  }

  /**
   * Sign a message according to the eth_sign web3 RPC call
   * @param bip32Path BIP 32 path to derive
   * @param message message to sign
   * @return ECDSA signature of the message
   */
  public ECDSADeviceSignature signPersonalMessage(String bip32Path, byte[] message) throws LedgerException {
    byte[] convertedPath = BIP32Helper.splitPath(bip32Path);
    int offset = 0;
    ApduExchange.ApduResponse response = null;
    while (offset != message.length) {
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      int maxBlockSize = (offset == 0 ? MAX_BLOCK_SIZE - convertedPath.length - 4 : MAX_BLOCK_SIZE);
      int blockSize = (offset + maxBlockSize > message.length ? message.length - offset : maxBlockSize);
      if (offset == 0) {
        out.write(convertedPath, 0, convertedPath.length);
        SerializeHelper.writeUint32BE(out, message.length);
      }
      out.write(Arrays.copyOfRange(message, offset, offset + blockSize), 0, blockSize);
      response = ApduExchange.exchangeApdu(device, TRX_CLA,
        INS_SIGN_PERSONAL_MESSAGE, 
        (offset == 0 ? P1_FIRST_BLOCK : P1_NEXT_BLOCK),
        0,
        out.toByteArray());
      response.checkSW();
      offset += blockSize;
    }
    byte[] responseData = response.getResponse();
    return new ECDSADeviceSignature((responseData[64] & 0xff), 
      Arrays.copyOfRange(responseData, 0, 0 + 32),
      Arrays.copyOfRange(responseData, 0 + 32, 0 + 32 + 32));    
  }

  /**
   * Retrieve the TRC 10 token information for a specific ID
   * @param id ID of the TRC10
   * @return token information to be used in signInfoTransaction or null if not available 
  */
  public byte[] getTrc10TokenInformation(Long id) {
    return TrxCache.lookupTrc10(id);
  }

  /**
   * Retrieve the Exchange information for a specific ID
   * @param id ID of the exchange
   * @return exchange information to be used in signInfoTransaction or null if not available 
  */
  public byte[] getExchangeInformation(Long id) {
    return TrxCache.lookupExchange(id);
  }

}
