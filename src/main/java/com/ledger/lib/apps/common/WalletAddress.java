package com.ledger.lib.apps.common;

import com.ledger.lib.utils.Dump;

  /**
   * \brief Information about a wallet address
   */
  public class WalletAddress {

    private String address;
    private byte[] publicKey;
    private byte[] chainCode;

    public WalletAddress(byte[] publicKey, String address, byte[] chainCode) {
      this.publicKey = publicKey;
      this.address = address;
      this.chainCode = chainCode;      
    }

    /** Return the uncompressed public key associated to this address */
    public byte[] getPublicKey() {      
      return publicKey;
    }

    /** Return the BIP 32 chaincode associated to this address */
    public byte[] getChaincode() {      
      return chainCode;
    }

    /** Return the address */
    public String getAddress() {      
      return address;
    }

    public String toString() {
      return address + " public key " + Dump.dump(publicKey) + " chainCode " + Dump.dump(chainCode);
    }
  }
