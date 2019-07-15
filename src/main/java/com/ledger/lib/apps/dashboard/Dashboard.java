package com.ledger.lib.apps.dashboard;

import java.util.Arrays;

import com.ledger.lib.LedgerException;
import com.ledger.lib.transport.LedgerDevice;
import com.ledger.lib.apps.LedgerApplication;
import com.ledger.lib.utils.ApduExchange;
import com.ledger.lib.utils.SW;
import com.ledger.lib.utils.SerializeHelper;
import com.ledger.lib.utils.Dump;

/**
 * \brief Communication with the device dashboard
 */
public class Dashboard extends LedgerApplication {

  /**
   * \brief Details about a BOLOS device
   */
  public class DeviceDetails {

    /** Set if the device is in recovery mode */
    public static final int FLAG_OS_RECOVERY = 0x01;
    /** Set if the integrity of the non secure chip has been verified */
    public static final int FLAG_OS_SIGNED_MCU = 0x02;
    /** Set if the user has been onboarded on the device */
    public static final int FLAG_OS_ONBOARDED = 0x04;
    /** Set if the issuer trust has been approved once during this session */
    public static final int FLAG_TRUST_ISSUER = 0x08;
    /** Set if a custom developer certificate trust has been approved once during this session */
    public static final int FLAG_TRUST_CUSTOMCA = 0x10;
    /** Set if the factory personalization has not been erased */
    public static final int FLAG_HSM_INITIALIZED = 0x20;
    /** Set if the user PIN has been validated for this session */
    public static final int FLAG_PIN_VALIDATED = 0x80;

    private long targetId;
    private String version;
    private int osFlags;
    private String mcuVersion;
    private byte[] mcuHash;

    DeviceDetails(byte[] response) {
      int offset = 0;      
      int nameLength;
      int flagSize;
      targetId = SerializeHelper.readUint32BE(response, offset);
      offset += 4;
      nameLength = (int)(response[offset++] & 0xff);
      version = SerializeHelper.readString(response, offset, nameLength);
      offset += nameLength;
      flagSize = (int)(response[offset++] & 0xff);
      osFlags = (int)(response[offset] & 0xff);
      offset += flagSize;
      if (offset < response.length) {
        nameLength = (int)(response[offset++] & 0xff);
        mcuVersion = SerializeHelper.readString(response, offset, nameLength);
        offset += nameLength;
        if (offset < response.length) {
          mcuHash = Arrays.copyOfRange(response, offset, offset + 32);
        }
      }
    }

    /** Return the Target ID identifying the device class */    
    public long getTargetId() {
      return targetId;
    }

    /** Return the OS version */
    public String getVersion() {
      return version;
    }

    /** Return the OS flags as a bitmask of the provided flags */
    public int getOSFlags() {
      return osFlags;
    }    

    /** Return the MCU version (or null if not present) */
    public String getMCUVersion() {
      return mcuVersion;
    }

    /** Return the MCU hash (or null if not present) */
    public byte[] getMCUHash() {
      return mcuHash;
    }

    /** Convert the OS flags to a string */
    public String osFlagsToString() {
      String result = "";
      if ((osFlags & FLAG_OS_RECOVERY) != 0) {
        result += "Recovery,";
      }
      if ((osFlags & FLAG_OS_SIGNED_MCU) != 0) {
        result += "Signed MCU,";
      }
      if ((osFlags & FLAG_OS_ONBOARDED) != 0) {
        result += "Onboarded,";
      }
      if ((osFlags & FLAG_TRUST_ISSUER) != 0) {
        result += "Trust issuer,";
      }
      if ((osFlags & FLAG_TRUST_CUSTOMCA) != 0) {
        result += "Trust Custom CA,";        
      }
      if ((osFlags & FLAG_HSM_INITIALIZED) != 0) {
        result += "Personalized,";
      }
      if ((osFlags & FLAG_PIN_VALIDATED) != 0) {
        result += "PIN ready,";
      }
      if (result.length() == 0) {
        return result;
      }
      else {
        return result.substring(0, result.length() - 1);
      }
    }

    public String toString() {
      String result = "0x" + Long.toHexString(targetId) + " " + version + " " + osFlagsToString();
      if (mcuVersion != null) {
        result += " MCU " + mcuVersion;
        if (mcuHash != null) {
          result += " " + Dump.dump(mcuHash);
        }
      }
      return result;
    }

  }

  private static final int CLA_BOLOS = 0xE0;
  private static final int INS_GET_VERSION = 0x01;
  private static final int INS_RUN_APP = 0xD8;

  /**
   * Constructor
   * @param device device to use
   */
  public Dashboard(LedgerDevice device) {
    super(device);
  }

  /** 
   * Return details about the device 
   * @return device details
   */
  public DeviceDetails getDeviceDetails() throws LedgerException {
    ApduExchange.ApduResponse response = ApduExchange.exchangeApdu(device, CLA_BOLOS, INS_GET_VERSION, 0, 0);
    response.checkSW();
    return new DeviceDetails(response.getResponse());
  }  

  /**
   * Run an application after getting the user approval
   * @return true if the application was found and launched
   */
  public boolean runApplication(String applicationName) throws LedgerException {    
    ApduExchange.ApduResponse response = ApduExchange.exchangeApdu(device, CLA_BOLOS, INS_RUN_APP, 0, 0, 
      SerializeHelper.stringToByteArray(applicationName));
    return (response.getSW() == SW.SW_OK);
  }  

}
