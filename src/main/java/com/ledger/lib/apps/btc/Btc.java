package com.ledger.lib.apps.btc;

import java.util.List;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Vector;
import java.util.HashMap;
import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.ledger.lib.LedgerException;
import com.ledger.lib.transport.LedgerDevice;
import com.ledger.lib.apps.LedgerApplication;
import com.ledger.lib.apps.common.WalletAddress;
import com.ledger.lib.apps.common.ECDSADeviceSignature;
import com.ledger.lib.utils.BIP32Helper;
import com.ledger.lib.utils.ApduExchange;
import com.ledger.lib.utils.SerializeHelper;
import com.ledger.lib.utils.VarintUtils;
import com.ledger.lib.utils.RIPEMD160Digest;
import com.ledger.lib.utils.Dump;

/**
 * \brief Communication with the device BTC application, and all forks based on the BTC application
 */
public class Btc extends LedgerApplication {

  /** \brief Type of Bitcoin addresses */
  public enum AddressFormat {    
    LEGACY, /** Legacy P2PKH address format */
    P2SH, /** Segwit P2WPKH over P2SH address format */
    BECH32 /** Native Segwit P2WPKH address format using Bech32 encoding */
  };

  /** \brief Internal input type passed to a transaction */
  private enum InputType {
    INPUT_TRUSTED, /** Trusted input computed by the device */
    INPUT_WITNESS /** Segregated witness input commiting to the amount */
  }

  /**
   * \brief Internal input passed to a transaction
  */
  private class TXInput {
    private InputType inputType;
    private byte[] value;

    public TXInput(InputType inputType, byte[] value) {
      this.inputType = inputType;
      this.value = value;
    }

    public InputType getInputType() {
      return inputType;
    }
    public byte[] getValue() {
      return value;
    }
  }

  private static final int BTC_CLA = 0xE0;
  private static final int INS_GET_WALLET_PUBLIC_KEY = 0x40;
  private static final int INS_GET_TRUSTED_INPUT = 0x42;
  private static final int INS_HASH_INPUT_START = 0x44;
  private static final int INS_HASH_INPUT_FINALIZE_FULL = 0x4A;
  private static final int INS_HASH_SIGN = 0x48;
  private static final int INS_SIGN_MESSAGE = 0x4E;

  private static final int P1_NO_DISPLAY = 0x00;
  private static final int P1_DISPLAY = 0x01;
  private static final int P2_LEGACY_ADDRESS = 0x00;
  private static final int P2_SEGWIT = 0x01;
  private static final int P2_SEGWIT_NATIVE = 0x02;
  private static final int P1_FIRST_BLOCK = 0x00;
  private static final int P1_NEXT_BLOCK = 0x80;
  private static final int P2_NEW_TX = 0x00;
  private static final int P2_NEW_TX_SEGWIT = 0x02;
  private static final int P2_CONTINUE_TX = 0x80;
  private static final int P2_CONTINUE_TX_SEGWIT = 0x10;
  private static final int P1_MORE_OUTPUT = 0x00;
  private static final int P1_LAST_OUTPUT = 0x80;
  private static final int P1_CHANGE_OUTPUT = 0xFF;
  private static final int P1_SIGN_MESSAGE_PREPARE = 0x00;
  private static final int P1_SIGN_MESSAGE_SIGN = 0x80;
  private static final int P2_SIGN_MESSAGE_PREPARE_FIRST = 0x01;
  private static final int P2_SIGN_MESSAGE_PREPARE_NEXT = 0x80;

  private static final int TAG_INPUT_TRUSTED = 0x01;
  private static final int TAG_INPUT_WITNESS = 0x02;

  private static final int SIGHASH_ALL = 0x01;

  private static final int MAX_BLOCK_SIZE = 255;

  private static final byte[] NULL_SCRIPT = new byte[0];

  private static final byte OP_DUP = 0x76;
  private static final byte OP_HASH160 = (byte)0xA9;
  private static final byte HASH160_SIZE = 0x14;
  private static final byte OP_EQUALVERIFY = (byte)0x88;
  private static final byte OP_CHECKSIG = (byte)0xAC;

  private MessageDigest sha256;
  private RIPEMD160Digest ripemd160;


  /**
   * Constructor
   * @param device device to use
   */
  public Btc(LedgerDevice device) {
    super(device);
    try {
      sha256 = MessageDigest.getInstance("SHA-256");
    }
    catch(NoSuchAlgorithmException e) {      
    }
    ripemd160 = new RIPEMD160Digest(); 
  }

  /**
   * Exchange a TX related APDU for the BTC app, splitting a large data blob into smaller chunks
   * @param device device to exchange the APDU with
   * @param cla APDU CLA
   * @param ins APDU INS
   * @param p1 APDU P1
   * @param p2 APDU P2
   * @param data data to exchange
   * @returns APDU data
   */
  private ApduExchange.ApduResponse exchangeApduSplit(LedgerDevice device, int cla, int ins, int p1, int p2, byte[] data) throws LedgerException {
    int offset = 0;
    ApduExchange.ApduResponse response = null;
    while (offset != data.length) {
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      int blockSize = (offset + MAX_BLOCK_SIZE > data.length ? data.length - offset : MAX_BLOCK_SIZE);
      out.write(Arrays.copyOfRange(data, offset, offset + blockSize), 0, blockSize);
      response = ApduExchange.exchangeApdu(device, cla, 
        ins, 
        p1,
        p2,
        out.toByteArray());
      response.checkSW();
      offset += blockSize;
    }
    return response;
  }

  /**
   * Exchange a TX related APDU for the BTC app, splitting a large data blob into smaller chunks and appending a smaller data blob at the end, making sure it fits into the same APDU
   * @param device device to exchange the APDU with
   * @param cla APDU CLA
   * @param ins APDU INS
   * @param p1 APDU P1
   * @param p2 APDU P2
   * @param data data to exchange
   * @param data2 smaller data blob to append
   * @returns APDU data
   */
  private ApduExchange.ApduResponse exchangeApduSplit(LedgerDevice device, int cla, int ins, int p1, int p2, byte[] data, byte[] data2) throws LedgerException {
    int offset = 0;
    int maxBlockSize = MAX_BLOCK_SIZE - data2.length;
    ApduExchange.ApduResponse response = null;
    while (offset != data.length) {
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      int blockSize = (offset + maxBlockSize > data.length ? data.length - offset : maxBlockSize);
      out.write(Arrays.copyOfRange(data, offset, offset + blockSize), 0, blockSize);
      if ((offset + blockSize) == data.length) {
        out.write(data2, 0, data2.length);
      }
      response = ApduExchange.exchangeApdu(device, cla, 
        ins, 
        p1,
        p2,
        out.toByteArray());
      response.checkSW();
      offset += blockSize;
    }
    if (data.length == 0) {
      response = ApduExchange.exchangeApdu(device, cla, 
        ins, 
        p1,
        p2,
        data2);
      response.checkSW();      
    }
    return response;
  }

  private TXInput getTrustedInput(BtcTransaction transaction, long index) throws LedgerException {
    ApduExchange.ApduResponse response;
    ByteArrayOutputStream data = new ByteArrayOutputStream();
    // Header
    SerializeHelper.writeUint32BE(data, index);
    SerializeHelper.writeBuffer(data, transaction.getVersion());
    VarintUtils.write(data, transaction.getInputs().size());
    response = ApduExchange.exchangeApdu(device, BTC_CLA, INS_GET_TRUSTED_INPUT, P1_FIRST_BLOCK, 0, data.toByteArray());
    response.checkSW();
    // Each input
    for (BtcTransaction.BtcInput input : transaction.getInputs()) {
      data = new ByteArrayOutputStream();
      SerializeHelper.writeBuffer(data, input.getPrevHash());
      SerializeHelper.writeUint32LE(data, input.getPrevIndex());
      VarintUtils.write(data, input.getScript().length);
      response = ApduExchange.exchangeApdu(device, BTC_CLA, INS_GET_TRUSTED_INPUT, P1_NEXT_BLOCK, 0, data.toByteArray());
      response.checkSW();
      data = new ByteArrayOutputStream();
      SerializeHelper.writeBuffer(data, input.getScript());
      exchangeApduSplit(device, BTC_CLA, INS_GET_TRUSTED_INPUT, P1_NEXT_BLOCK, 0, data.toByteArray(), input.getSequence());      
    }
    // Number of outputs
    data = new ByteArrayOutputStream();
    VarintUtils.write(data, transaction.getOutputs().size());
    response = ApduExchange.exchangeApdu(device, BTC_CLA, INS_GET_TRUSTED_INPUT, P1_NEXT_BLOCK, 0, data.toByteArray());
    response.checkSW();
    // Each output
    for (BtcTransaction.BtcOutput output : transaction.getOutputs()) {
      data = new ByteArrayOutputStream();
      SerializeHelper.writeBuffer(data, output.getAmount());
      VarintUtils.write(data, output.getScript().length);
      response = ApduExchange.exchangeApdu(device, BTC_CLA, INS_GET_TRUSTED_INPUT, P1_NEXT_BLOCK, 0, data.toByteArray());
      response.checkSW();
      data = new ByteArrayOutputStream();
      SerializeHelper.writeBuffer(data, output.getScript());
      response = exchangeApduSplit(device, BTC_CLA, INS_GET_TRUSTED_INPUT, P1_NEXT_BLOCK, 0, data.toByteArray());            
      response.checkSW();
    }
    // Locktime
    response = ApduExchange.exchangeApdu(device, BTC_CLA, INS_GET_TRUSTED_INPUT, P1_NEXT_BLOCK, 0, transaction.getLockTime());    
    response.checkSW();
    return new TXInput(InputType.INPUT_TRUSTED, Arrays.copyOfRange(response.getResponse(), 0, response.getResponse().length - 2));
  }  

  private byte[] getTXHash(BtcTransaction transaction) throws LedgerException {
    byte[] serializedTx = transaction.serialize(false, true);
    byte[] digest = sha256.digest(serializedTx);
    digest = sha256.digest(digest);
    return digest;
  }

  private AddressFormat scanOutputScriptFormat(byte[] outputScript) {
    if (outputScript.length < 3) {
      return null;
    }
    if ((outputScript.length == 2 + 1 + 20 + 2) && (outputScript[0] == OP_DUP) && (outputScript[1] == OP_HASH160)) {
      return AddressFormat.LEGACY;
    }
    if ((outputScript.length == 1 + 1 + 20 + 1) && (outputScript[0] == OP_HASH160)) {
      return AddressFormat.P2SH;
    }
    if ((outputScript.length == 1 + 1 + 20) && (outputScript[0] == 0) && (outputScript[1] == HASH160_SIZE)) {
      return AddressFormat.BECH32;
    }
    return null;
  }

  private TXInput getTrustedInputBIP143(BtcTransaction transaction, byte[] txHash, long index) throws LedgerException {
    if (sha256 == null) {
      throw new LedgerException(LedgerException.ExceptionReason.INTERNAL_ERROR, "SHA-256 not available");      
    }
    if ((index < 0) || (index >= transaction.getOutputs().size())) {
      throw new LedgerException(LedgerException.ExceptionReason.INVALID_PARAMETER, "Invalid output reference");
    }
    ByteArrayOutputStream data = new ByteArrayOutputStream(32 + 4 + 8);
    if (txHash == null) {
      txHash = getTXHash(transaction);  
    }    
    SerializeHelper.writeBuffer(data, txHash);
    SerializeHelper.writeUint32LE(data, index);
    data.write(transaction.getOutputs().get((int)index).getAmount(), 0, 8);
    return new TXInput(InputType.INPUT_WITNESS, data.toByteArray());
  }

  private TXInput getTrustedInputBIP143(BtcTransaction transaction, long index) throws LedgerException {
    return getTrustedInputBIP143(transaction, null, index);
  }

  private TXInput getTrustedInputBIP143(TXInput input) throws LedgerException {
    if (input.getInputType() == InputType.INPUT_WITNESS) {
      return input;
    }
    return new TXInput(InputType.INPUT_WITNESS, Arrays.copyOfRange(input.getValue(), 4, 4 + 32 + 4 + 8));
  }

  private byte[] compressPublicKey(byte[] publicKey) throws LedgerException {
    if (publicKey.length == 1 + 32) {
      return publicKey;
    }
    if ((publicKey.length != 1 + 64) || (publicKey[0] != 0x04)) {
      throw new LedgerException(LedgerException.ExceptionReason.INVALID_PARAMETER, "Unsupported public key format " + Dump.dump(publicKey));
    }
    ByteArrayOutputStream out = new ByteArrayOutputStream(1 + 32);
    if ((publicKey[64] & 1) != 0) {
      out.write(0x03);
    }
    else {
      out.write(0x02);
    }
    out.write(publicKey, 1, 32);
    return out.toByteArray();
  }

  private byte[] hashPublicKey(byte[] publicKey) throws LedgerException {
    byte[] hash160 = new byte[20];
    byte[] hashedPublicKey = sha256.digest(publicKey);
    ripemd160.update(hashedPublicKey, 0, hashedPublicKey.length);
    ripemd160.doFinal(hash160, 0);
    return hash160;
  }

  private byte[] getRedeemScriptBIP143(byte[] publicKey) throws LedgerException {
    ByteArrayOutputStream redeemScript = new ByteArrayOutputStream(3 + 20 + 2);
    byte[] hash160 = hashPublicKey(publicKey);
    redeemScript.write(OP_DUP);
    redeemScript.write(OP_HASH160);
    redeemScript.write(HASH160_SIZE);
    SerializeHelper.writeBuffer(redeemScript, hash160);
    redeemScript.write(OP_EQUALVERIFY);
    redeemScript.write(OP_CHECKSIG);
    return redeemScript.toByteArray();
  }

  private byte[] getRedeemScript(BtcTransaction.BtcInput input, AddressFormat addressFormat, BtcTransaction parentTransaction, byte[] associatedPublicKey) throws LedgerException {
    // If a redeem script is associated to this input, it's prefereed
    byte[] redeemScript = input.getScript();
    if ((redeemScript != null) && (redeemScript.length != 0)) {
      return redeemScript;
    }
    switch(addressFormat) {
      case LEGACY:
        redeemScript = parentTransaction.getOutputs().get((int)input.getPrevIndex()).getScript();
        break;
      case P2SH:
      case BECH32:
        redeemScript = getRedeemScriptBIP143(associatedPublicKey);
        break;
    }
    return redeemScript;
  }

  private byte[] getRedeemScript(BtcTransaction.BtcInput input, BtcTransaction parentTransaction) throws LedgerException {
    return getRedeemScript(input, AddressFormat.LEGACY, parentTransaction, null);
  }

  private byte[] getRedeemScript(BtcTransaction.BtcInput input, AddressFormat addressFormat, byte[] publicKey) {
    return getRedeemScript(input, addressFormat, null, publicKey);
  }

  private void startUntrustedTransaction(BtcTransaction transaction, boolean newTransaction, boolean continueSegwit, long inputIndex, TXInput usedInputList[], byte[] redeemScript) throws LedgerException {
    ApduExchange.ApduResponse response;
    // Check inputs consistency
    if (usedInputList.length != transaction.getInputs().size()) {
      throw new LedgerException(LedgerException.ExceptionReason.INVALID_PARAMETER, "Invalid number of inputs passed");
    }
    boolean segwit = false;
    for (TXInput currentInput : usedInputList) {
      if (currentInput.getInputType() == InputType.INPUT_WITNESS) {
        segwit = true;
        break;
      }
    }
    ByteArrayOutputStream data = new ByteArrayOutputStream();
    SerializeHelper.writeBuffer(data, transaction.getVersion());
    VarintUtils.write(data, transaction.getInputs().size());
    int p2 = (newTransaction ? (segwit ? P2_NEW_TX_SEGWIT : P2_NEW_TX) : (continueSegwit ? P2_CONTINUE_TX_SEGWIT : P2_CONTINUE_TX));
    response = ApduExchange.exchangeApdu(device, BTC_CLA, INS_HASH_INPUT_START, P1_FIRST_BLOCK, p2, data.toByteArray());
    response.checkSW();
    long currentIndex = 0;
    for (BtcTransaction.BtcInput currentInput : transaction.getInputs()) {
      TXInput deviceInput = usedInputList[(int)currentIndex];
      byte[] script = (currentIndex == inputIndex ? redeemScript : NULL_SCRIPT);
      data = new ByteArrayOutputStream();
      switch(deviceInput.getInputType()) {
        case INPUT_TRUSTED:
          data.write(TAG_INPUT_TRUSTED);
          data.write(deviceInput.getValue().length);
          break;
        case INPUT_WITNESS:
          data.write(TAG_INPUT_WITNESS);
          break;
      }
      SerializeHelper.writeBuffer(data, deviceInput.getValue());
      VarintUtils.write(data, script.length);
      response = ApduExchange.exchangeApdu(device, BTC_CLA, INS_HASH_INPUT_START, P1_NEXT_BLOCK, 0, data.toByteArray());
      response.checkSW();
      data = new ByteArrayOutputStream();
      SerializeHelper.writeBuffer(data, script);
      SerializeHelper.writeBuffer(data, currentInput.getSequence());
      response = exchangeApduSplit(device, BTC_CLA, INS_HASH_INPUT_START, P1_NEXT_BLOCK, 0, data.toByteArray());            
      response.checkSW();      
      currentIndex++;
    }
  }

  private void provideOutputFullChangePath(String bip32Path) throws LedgerException {
    byte[] convertedPath = BIP32Helper.splitPath(bip32Path);
    ApduExchange.ApduResponse response = ApduExchange.exchangeApdu(device, BTC_CLA, INS_HASH_INPUT_FINALIZE_FULL, P1_CHANGE_OUTPUT, 0, convertedPath);
    response.checkSW();
  }

  private void hashOutputFull(byte[] output) throws LedgerException {
    int offset = 0;
    ApduExchange.ApduResponse response = null;
    while (offset != output.length) {
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      int blockSize = (offset + MAX_BLOCK_SIZE > output.length ? output.length - offset : MAX_BLOCK_SIZE);
      out.write(Arrays.copyOfRange(output, offset, offset + blockSize), 0, blockSize);
      response = ApduExchange.exchangeApdu(device, BTC_CLA, 
        INS_HASH_INPUT_FINALIZE_FULL, 
        ((offset + blockSize) == output.length ? P1_LAST_OUTPUT : P1_MORE_OUTPUT),
        0,
        out.toByteArray());
      response.checkSW();
      offset += blockSize;
    }    
  }

  private byte[] signTransaction(BtcTransaction transaction, String bip32Path) throws LedgerException {
    byte[] convertedPath = BIP32Helper.splitPath(bip32Path);
    ApduExchange.ApduResponse response = null;
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    SerializeHelper.writeBuffer(out, convertedPath);
    out.write(0);
    SerializeHelper.writeBuffer(out, transaction.getLockTime());
    out.write(SIGHASH_ALL);
    response = ApduExchange.exchangeApdu(device, BTC_CLA, INS_HASH_SIGN, 0, 0, out.toByteArray());
    response.checkSW();
    return Arrays.copyOfRange(response.getResponse(), 0, response.getResponse().length - 2);
  }


  /**
   * Get information about a wallet address
   * @param bip32Path BIP 32 path to derive
   * @param verify true if the address shall be prompted to the user for verification
   * @param format format of the address
   * @return information about the address
   */
  public WalletAddress getWalletAddress(String bip32Path, boolean verify, AddressFormat format) throws LedgerException {
    byte[] convertedPath = BIP32Helper.splitPath(bip32Path);
    int p2 = P2_LEGACY_ADDRESS;
    switch(format) {
      case LEGACY:
        p2 = P2_LEGACY_ADDRESS;
        break;
      case P2SH:
        p2 = P2_SEGWIT;
        break;
      case BECH32:
        p2 = P2_SEGWIT_NATIVE;
        break;
    }
    ApduExchange.ApduResponse response = ApduExchange.exchangeApdu(device, BTC_CLA, 
      INS_GET_WALLET_PUBLIC_KEY, 
      (verify ? P1_DISPLAY : P1_NO_DISPLAY),
      p2,
      convertedPath);
    response.checkSW();
    return SerializeHelper.readWalletAddress(response.getResponse());
  }  

  /**
   * Sign a P2PKH transaction
   * @param BtcTransaction unsigned transaction to sign. Each scriptsig will be used as redeem script when present.
   * @param parentTransactions list of parent transactions used as prevouts in the unsigned transaction. The list doesn't need to be ordered.
   * @param associatedKeysets ordered BIP 32 path of each private key associated to each UTXO
   * @param changePath optional BIP 32 path of the public key used to compute the change address (or null)
   * @return the signed transasction ready to be broadcast
   */
  public BtcTransaction signP2PKHTransaction(BtcTransaction unsignedTransaction, List<BtcTransaction> parentTransactions, List<String> associatedKeysets, String changePath) throws LedgerException {
    Vector<AddressFormat> outputType = new Vector<AddressFormat>(unsignedTransaction.getInputs().size());    
    HashMap<String, BtcTransaction> txs = new HashMap<String, BtcTransaction>(parentTransactions.size());
    HashMap<String, byte[]> publicKeys = new HashMap(associatedKeysets.size());
    byte[][] signatures = new byte[associatedKeysets.size()][];
    TXInput[] txInputs = new TXInput[associatedKeysets.size()];
    byte[] serializedOutputs = unsignedTransaction.serializeOutputs();
    int index;
    boolean segwitInputFound = false;
    boolean legacyInputFound = false;
    boolean newTx = true;
    boolean changeProvided = false;
    ByteArrayOutputStream witness = new ByteArrayOutputStream();
    // Early sanity checks
    if (associatedKeysets.size() != unsignedTransaction.getInputs().size()) {
      throw new LedgerException(LedgerException.ExceptionReason.INVALID_PARAMETER, "Number of inputs to sign and provided key paths not matching");
    }
    // Populate the transactions map
    for (BtcTransaction tx : parentTransactions) {
      txs.put(Dump.dump(getTXHash(tx)), tx);
    }
    // Later sanity checks 
    for (BtcTransaction.BtcInput input : unsignedTransaction.getInputs()) {
      BtcTransaction previousTx = txs.get(Dump.dump(input.getPrevHash()));
      BtcTransaction.BtcOutput previousOutput;
      AddressFormat previousOutputFormat;
      if (previousTx == null) {
        throw new LedgerException(LedgerException.ExceptionReason.INVALID_PARAMETER, "Missing input " + Dump.dump(input.getPrevHash()));
      }
      if (input.getPrevIndex() > previousTx.getOutputs().size()) {
        throw new LedgerException(LedgerException.ExceptionReason.INVALID_PARAMETER, "Missing input " + Dump.dump(input.getPrevHash()) + ":" + input.getPrevIndex());
      }      
      previousOutput = previousTx.getOutputs().get((int)input.getPrevIndex());
      previousOutputFormat = scanOutputScriptFormat(previousOutput.getScript());
      if (previousOutputFormat == null) {
        throw new LedgerException(LedgerException.ExceptionReason.INVALID_PARAMETER, "Unrecognized script format for " + Dump.dump(input.getPrevHash()) + ":" + input.getPrevIndex());        
      }
      switch(previousOutputFormat) {
        case LEGACY:
          legacyInputFound = true;
          break;
        case P2SH:
        case BECH32:
          segwitInputFound = true;
          break;
      }
      outputType.add(previousOutputFormat);      
    }
    // Collect all associated public keys
    for (String keyPath : associatedKeysets) {
      if (!publicKeys.containsKey(keyPath)) {
        WalletAddress walletAddress = getWalletAddress(keyPath, false, AddressFormat.LEGACY);        
        publicKeys.put(keyPath, compressPublicKey(walletAddress.getPublicKey()));
      }
    }    
    // Create trusted inputs     
    index = 0;
    for (BtcTransaction.BtcInput input : unsignedTransaction.getInputs()) {
      BtcTransaction previousTx = txs.get(Dump.dump(input.getPrevHash()));
      TXInput trustedInput;
      // If all tx inputs aren't using Segwit, collect all Trusted Inputs from the device
      if (legacyInputFound) {        
        trustedInput = getTrustedInput(previousTx, input.getPrevIndex());
      }
      else {
        trustedInput = getTrustedInputBIP143(previousTx, input.getPrevIndex());
      }
      txInputs[index] = trustedInput;
      index++;
    }
    // Handle non Segwit signing     
    if (legacyInputFound) {      
      index = 0;
      for (BtcTransaction.BtcInput input : unsignedTransaction.getInputs()) {
        if (outputType.get(index).equals(AddressFormat.LEGACY)) {
          byte[] redeemScript = getRedeemScript(input, txs.get(Dump.dump(input.getPrevHash())));
          startUntrustedTransaction(unsignedTransaction, newTx, false, index, txInputs, redeemScript);
          newTx = false;
          if (!changeProvided && (changePath != null) && (changePath.length() != 0)) {
            provideOutputFullChangePath(changePath);
            changeProvided = true;
          }
          hashOutputFull(serializedOutputs);
          signatures[index] = signTransaction(unsignedTransaction, associatedKeysets.get(index));
        }
        index++;
      }
    }
    // Handle Segwit signing
    if (segwitInputFound) {      
      if (legacyInputFound) {
        for (int i=0; i<txInputs.length; i++) {
          txInputs[i] = getTrustedInputBIP143(txInputs[i]);
        }
      }
      TXInput[] txInput = new TXInput[1];
      startUntrustedTransaction(unsignedTransaction, newTx, legacyInputFound, 0, txInputs, NULL_SCRIPT);
      newTx = false;
      if (!changeProvided && (changePath != null) && (changePath.length() != 0)) {
        provideOutputFullChangePath(changePath);
        changeProvided = true;
      }
      hashOutputFull(serializedOutputs);
      index = 0;
      for (BtcTransaction.BtcInput input : unsignedTransaction.getInputs()) {
        if (outputType.get(index).equals(AddressFormat.P2SH) || outputType.get(index).equals(AddressFormat.BECH32)) {
          BtcTransaction tx = new BtcTransaction();
          tx.addInput(input);
          tx.setVersion(unsignedTransaction.getVersion());
          tx.setLockTime(unsignedTransaction.getLockTime());
          txInput[0] = txInputs[index];
          byte[] redeemScript = getRedeemScript(input, outputType.get(index), publicKeys.get(associatedKeysets.get(index)));
          startUntrustedTransaction(tx, false, false, 0, txInput, redeemScript);
          signatures[index] = signTransaction(unsignedTransaction, associatedKeysets.get(index)); 
        }
        index++;
      }
    }
    // Finalize transaction signing filling scriptSig and witness
    index = 0;
    for (BtcTransaction.BtcInput input : unsignedTransaction.getInputs()) {
      ByteArrayOutputStream scriptSig = new ByteArrayOutputStream();
      ByteArrayOutputStream localWitness = new ByteArrayOutputStream();
      byte[] publicKey = publicKeys.get(associatedKeysets.get(index));
      switch(outputType.get(index)) {
        case LEGACY:
          scriptSig.write(signatures[index].length);
          SerializeHelper.writeBuffer(scriptSig, signatures[index]);
          scriptSig.write(publicKey.length);
          SerializeHelper.writeBuffer(scriptSig, publicKey);
          break;
        case P2SH:  
          scriptSig.write(0x16);
          scriptSig.write(0x00);
          scriptSig.write(0x14);
          SerializeHelper.writeBuffer(scriptSig, hashPublicKey(publicKey));
          break;
        case BECH32:
          break;
      }
      switch(outputType.get(index)) {
        case LEGACY:
          if (segwitInputFound) {
            localWitness.write(0);
          }        
          break;
        case P2SH:
        case BECH32:
          localWitness.write(2);
          localWitness.write(signatures[index].length);
          SerializeHelper.writeBuffer(localWitness, signatures[index]);
          localWitness.write(publicKey.length);
          SerializeHelper.writeBuffer(localWitness, publicKey);          
          break;
      }
      input.setScript(scriptSig.toByteArray());
      if (segwitInputFound) {
        SerializeHelper.writeBuffer(witness, localWitness.toByteArray());
      }
      index++;
    }
    if (segwitInputFound) {
      unsignedTransaction.setWitness(witness.toByteArray());
    }
    return unsignedTransaction;
  }

  /**
   * Sign a message according to the Bitcoin Signature format
   * @param bip32Path BIP 32 path to derive
   * @param message message to sign
   * @return ECDSA signature of the message
   */
  public ECDSADeviceSignature signMessage(String bip32Path, byte[] message) throws LedgerException {
    byte[] convertedPath = BIP32Helper.splitPath(bip32Path);
    ApduExchange.ApduResponse response = null;
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    int offset = 0;
    while (offset != message.length) {
      out = new ByteArrayOutputStream();
      if (offset == 0) {
        SerializeHelper.writeBuffer(out, convertedPath);
        SerializeHelper.writeUint16BE(out, message.length);
      }
      int maxBlockSize = MAX_BLOCK_SIZE - out.size();
      int blockSize = (offset + maxBlockSize > message.length ? message.length - offset : maxBlockSize);
      out.write(Arrays.copyOfRange(message, offset, offset + blockSize), 0, blockSize);
      response = ApduExchange.exchangeApdu(device, BTC_CLA, 
        INS_SIGN_MESSAGE, 
        P1_SIGN_MESSAGE_PREPARE,
        (offset == 0 ? P2_SIGN_MESSAGE_PREPARE_FIRST : P2_SIGN_MESSAGE_PREPARE_NEXT),
        out.toByteArray());
      response.checkSW();
      offset += blockSize;
    }
    out = new ByteArrayOutputStream();
    out.write(0);
    response = ApduExchange.exchangeApdu(device, BTC_CLA, 
      INS_SIGN_MESSAGE, 
      P1_SIGN_MESSAGE_SIGN,
      0,
      out.toByteArray());
    response.checkSW();
    byte[] signatureResponse = Arrays.copyOfRange(response.getResponse(), 0, response.getResponse().length - 2);
    return new ECDSADeviceSignature(signatureResponse[0] - 0x30, signatureResponse);
  }
}
