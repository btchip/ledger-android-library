package com.ledger.lib.apps;

import java.util.Arrays;

import com.ledger.lib.LedgerException;
import com.ledger.lib.WrongApplicationException;
import com.ledger.lib.transport.LedgerDevice;
import com.ledger.lib.utils.ApduExchange;
import com.ledger.lib.utils.SW;
import com.ledger.lib.utils.SerializeHelper;

/**
 * \brief Generic Ledger application exposing default primitives common to all device applications
 */
public class LedgerApplication {

  /**
   * \brief Details about a BOLOS application
   */
  public class ApplicationDetails {

    private static final int APP_DETAILS_FORMAT_VERSION = 1;

    private String name;
    private String version;
    private int flags;

    ApplicationDetails(byte[] response) {
      int offset = 0;      
      if (response[offset++] != APP_DETAILS_FORMAT_VERSION) {
        throw new LedgerException(LedgerException.ExceptionReason.INTERNAL_ERROR, "Unsupported application format");      
      }
      int nameLength = (response[offset++] & 0xff);
      name = SerializeHelper.readString(response, offset, nameLength);
      offset += nameLength;
      int versionLength = (response[offset++] & 0xff);
      version = SerializeHelper.readString(response, offset, versionLength);
      offset += versionLength;
      flags = (response[offset++] & 0xff);
    }

    /** Return the application name */
    public String getName() {
      return name;
    }

    /** Return the application version */
    public String getVersion() {
      return version;
    }

    /** Return the application flags */
    public int getFlags() {
      return flags;
    }

    public String toString() {
      return name + " " + version + " " + Integer.toHexString(flags);
    }
  }

  private static final int CLA_COMMON_SDK = 0xB0;
  private static final int INS_GET_APP_NAME_AND_VERSION = 0x01;
  private static final int INS_GET_WALLET_ID = 0x04;
  private static final int INS_GET_WALLET_ID_NATIVE = 0x02;
  private static final int INS_EXIT = 0xA7;

  private static final int NATIVE_WALLET_ID_FORMAT = 1;

  protected LedgerDevice device;

  /**
   * Constructor
   * @param device device to use
   */
  public LedgerApplication(LedgerDevice device) {    
    this.device = device;
  }

  /** 
   * Return details about the currently running application on device 
   * @return application details
   */
  public ApplicationDetails getApplicationDetails() throws LedgerException {
    ApduExchange.ApduResponse response = ApduExchange.exchangeApdu(device, CLA_COMMON_SDK, INS_GET_APP_NAME_AND_VERSION, 0, 0);
    response.checkSW();
    return new ApplicationDetails(response.getResponse());
  }  

  /**
   * Return the wallet ID, unique for a given current seed
   * @return wallet ID
   */
  public byte[] getWalletID() throws LedgerException {
    ApduExchange.ApduResponse response = ApduExchange.exchangeApdu(device, CLA_COMMON_SDK, INS_GET_WALLET_ID_NATIVE, 0, 0);    
    if (response.getSW() == SW.SW_OK) {
      byte[] responseData = response.getResponse();
      if (responseData[0] != NATIVE_WALLET_ID_FORMAT) {
        throw new LedgerException(LedgerException.ExceptionReason.INTERNAL_ERROR, "Unsupported Wallet ID format");
      }
      int idLength = (int)(responseData[1] & 0xff);
      return Arrays.copyOfRange(responseData, 2, idLength + 2);
    }    
    response = ApduExchange.exchangeApdu(device, CLA_COMMON_SDK, INS_GET_WALLET_ID, 0, 0);    
    if (response.getSW() == SW.SW_OK) {
      byte[] responseData = response.getResponse();
      return Arrays.copyOfRange(responseData, 0, responseData.length - 2);
    }
    else {
      throw new WrongApplicationException();
    }
  }

  /**
   * Exit the currently running application, going back to the dashboard without user confirmation
   * @return true if supported
   */
  public boolean exitApplication() throws LedgerException {    
    ApduExchange.ApduResponse response = ApduExchange.exchangeApdu(device, CLA_COMMON_SDK, INS_EXIT, 0, 0);
    return (response.getSW() == SW.SW_OK);
  }

}
