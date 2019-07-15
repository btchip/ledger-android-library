package com.ledger.lib.apps.common;

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
