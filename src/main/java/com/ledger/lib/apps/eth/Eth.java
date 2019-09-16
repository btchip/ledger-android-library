package com.ledger.lib.apps.eth;

import java.util.Arrays;
import java.io.ByteArrayOutputStream;

import com.ledger.lib.LedgerException;
import com.ledger.lib.transport.LedgerDevice;
import com.ledger.lib.apps.LedgerApplication;
import com.ledger.lib.apps.common.WalletAddress;
import com.ledger.lib.apps.common.ECDSADeviceSignature;
import com.ledger.lib.utils.BIP32Helper;
import com.ledger.lib.utils.ApduExchange;
import com.ledger.lib.utils.SerializeHelper;
import com.ledger.lib.apps.common.ECDSADeviceSignature;

/**
 * \brief Communication with the device ETH application, and all forks based on the ETH application
 */
public class Eth extends LedgerApplication {

  /**
   * \brief Details about the ETH application
   */
  public class EthConfiguration {

    /** Set if arbitrary contract data signing is allowed by the user */
    public static final int FLAG_DATA_ALLOWED = 0x01;
    /** Set if ERC 20 token information has to be provided by the caller */
    public static final int FLAG_EXTERNAL_TOKEN_NEEDED = 0x02;
    
    private int flags;

    EthConfiguration(byte[] response) {
      int offset = 0;      
      flags = (response[offset++] & 0xff);
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
      if ((flags & FLAG_EXTERNAL_TOKEN_NEEDED) != 0) {
        result += "External ERC 20 information required,";
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

  private static final int ETH_CLA = 0xE0;
  private static final int INS_GET_PUBLIC_ADDRESS = 0x02;
  private static final int INS_SIGN_TRANSACTION = 0x04;
  private static final int INS_GET_APPLICATION_CONFIGURATION = 0x06;
  private static final int INS_SIGN_PERSONAL_MESSAGE = 0x08;
  private static final int INS_PROVIDE_ERC20_TOKEN_INFORMATION = 0x0A;

  private static final int P1_NO_DISPLAY = 0x00;
  private static final int P1_DISPLAY = 0x01;
  private static final int P2_NO_CHAINCODE = 0x00;
  private static final int P2_CHAINCODE = 0x01;
  private static final int P1_FIRST_BLOCK = 0x00;
  private static final int P1_NEXT_BLOCK = 0x80;

  private static final int MAX_BLOCK_SIZE = 255;

  /**
   * Constructor
   * @param device device to use
   */
  public Eth(LedgerDevice device) {
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
    ApduExchange.ApduResponse response = ApduExchange.exchangeApdu(device, ETH_CLA, 
      INS_GET_PUBLIC_ADDRESS, 
      (verify ? P1_DISPLAY : P1_NO_DISPLAY),
      P2_CHAINCODE,
      convertedPath);
    response.checkSW();
    return SerializeHelper.readWalletAddress(response.getResponse());
  }  

  private ECDSADeviceSignature signMessageOrTransaction(int ins, String bip32Path, byte[] rawTransaction, boolean signMsg) throws LedgerException {
    byte[] convertedPath = BIP32Helper.splitPath(bip32Path);
    int offset = 0;
    int extra = (signMsg ? 4 : 0);
    ApduExchange.ApduResponse response = null;
    while (offset != rawTransaction.length) {
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      int maxBlockSize = (offset == 0 ? MAX_BLOCK_SIZE - convertedPath.length - extra : MAX_BLOCK_SIZE);
      int blockSize = (offset + maxBlockSize > rawTransaction.length ? rawTransaction.length - offset : maxBlockSize);
      if (offset == 0) {
        out.write(convertedPath, 0, convertedPath.length);
        if (signMsg) {
          SerializeHelper.writeUint32BE(out, rawTransaction.length);
        }
      }
      out.write(Arrays.copyOfRange(rawTransaction, offset, offset + blockSize), 0, blockSize);
      response = ApduExchange.exchangeApdu(device, ETH_CLA, 
        ins, 
        (offset == 0 ? P1_FIRST_BLOCK : P1_NEXT_BLOCK),
        0,
        out.toByteArray());
      response.checkSW();
      offset += blockSize;
    }
    byte[] responseData = response.getResponse();
    return new ECDSADeviceSignature((responseData[0] & 0xff), 
      Arrays.copyOfRange(responseData, 1, 1 + 32),
      Arrays.copyOfRange(responseData, 1 + 32, 1 + 32 + 32));    
  }


  /**
   * Sign an Ethereum transaction
   * @param bip32Path BIP 32 path to derive
   * @param rawTranasction serialized transaction to sign
   * @return ECDSA signature of the transaction
   */
  public ECDSADeviceSignature signTransaction(String bip32Path, byte[] rawTransaction) throws LedgerException {
    return signMessageOrTransaction(INS_SIGN_TRANSACTION, bip32Path, rawTransaction, false);
  }

  /**
   * Sign an Ethereum transaction involving an ERC 20 contract transfer
   * If a token information is available, the device will display specific information about the token
   * @param bip32Path BIP 32 path to derive
   * @param rawTranasction serialized transaction to sign
   * @param tokenInformation blob encoding the token information or null if not available - can be obtained through getErc20TokenInformation or using an external provider
   * @return ECDSA signature of the transaction
   */
  public ECDSADeviceSignature signErc20Transaction(String bip32Path, byte[] rawTransaction, byte[] tokenInformation) throws LedgerException {
    if (tokenInformation != null) {
      ApduExchange.ApduResponse response = ApduExchange.exchangeApdu(device, ETH_CLA,
        INS_PROVIDE_ERC20_TOKEN_INFORMATION,
        0, 0, 
        tokenInformation);
      response.checkSW();
    }
    return signTransaction(bip32Path, rawTransaction);
  }

  /**
   * Retrieve the ERC 20 token information for a specific contract address
   * @param contractAddress address of the ERC 20 token
   * @return token information to be used in signErc20Transaction or null if not available 
  */
  public byte[] getErc20TokenInformation(String contractAddress) {
    return Erc20Cache.lookup(contractAddress);
  }

  /**
   * Sign a message according to the eth_sign web3 RPC call
   * @param bip32Path BIP 32 path to derive
   * @param message message to sign
   * @return ECDSA signature of the message
   */
  public ECDSADeviceSignature signPersonalMessage(String bip32Path, byte[] message) throws LedgerException {
    return signMessageOrTransaction(INS_SIGN_PERSONAL_MESSAGE, bip32Path, message, true);
  }

  /** 
   * Return the application configuration
   * @return application configuration
   */
  public EthConfiguration getConfiguration() throws LedgerException {
    ApduExchange.ApduResponse response = ApduExchange.exchangeApdu(device, ETH_CLA, INS_GET_APPLICATION_CONFIGURATION, 0, 0);
    response.checkSW();
    return new EthConfiguration(response.getResponse());
  }  


}
