package com.ledger.lib.apps.common;

import java.util.Arrays;
import java.io.ByteArrayOutputStream;

import com.ledger.lib.utils.Dump;

  /**
   * \brief ECDSA Signature returned by the device
   */
  public class ECDSADeviceSignature {

    private int v;
    private byte[] r;
    private byte[] s;    

    public ECDSADeviceSignature(int v, byte[] r, byte[] s) {
      this.v = v;
      this.r = r;
      this.s = s;
    }

    public ECDSADeviceSignature(int v, byte[] derSignature) {
      this.v = v;
      int offset = 4;
      this.r = Arrays.copyOfRange(derSignature, offset, offset + derSignature[offset - 1]);
      if (this.r[0] == 0) {
        this.r = Arrays.copyOfRange(this.r, 1, this.r.length);
      }
      offset += derSignature[offset - 1] + 2;
      this.s = Arrays.copyOfRange(derSignature, offset, offset + derSignature[offset - 1]);
      if (this.s[0] == 0) {
        this.s = Arrays.copyOfRange(this.s, 1, this.s.length);
      }
    }

    /** Get the recovery information (v) of the signature */
    public int getRecoveryInformation() {
      return v;
    }

    /** Get the R part of the signature */
    public byte[] getR() {
      return r;
    }

    /** Get the S part of the signature */
    public byte[] getS() {      
      return s;
    }

    /** Get the DER representation of the signature */
    public byte[] getDER() {
      return null;
    }

    public String toString() {
      return "r " + Dump.dump(r) + " s " + Dump.dump(s) + " v " + v;
    }
  }
