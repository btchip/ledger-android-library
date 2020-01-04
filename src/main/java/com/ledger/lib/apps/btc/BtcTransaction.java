package com.ledger.lib.apps.btc;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Vector;

import com.ledger.lib.utils.SerializeHelper;
import com.ledger.lib.utils.Dump;
import com.ledger.lib.utils.VarintUtils;

import com.ledger.lib.LedgerException;

/**
 * \brief Internal representation of a Bitcoin transaction
 */
public class BtcTransaction {

  /**
   * \brief Internal representation of a Bitcoin transaction input
  */  
  public class BtcInput {
    
    /** Hash of the previous transaction */
    private byte[] prevHash;
    /** Index in the previous transaction */
    private long prevIndex;
    /** Serialized scriptSig */
    private byte[] script;
    /** Serialzied sequence */
    private byte[] sequence;

    /** 
     * Input constructor from raw data
     * @param data serialized input data
     */    
    public BtcInput(ByteArrayInputStream data) throws LedgerException { 
      try {
        byte[] prevIndexSerialized = new byte[4];
        prevHash = new byte[32];
        data.read(prevHash);     
        data.read(prevIndexSerialized);
        prevIndex = SerializeHelper.readUint32LE(prevIndexSerialized, 0);
        long scriptSize = VarintUtils.read(data);
        script = new byte[(int)scriptSize];
        data.read(script);
        sequence = new byte[4];
        data.read(sequence);
      }
      catch(Exception e) {
        throw new LedgerException(LedgerException.ExceptionReason.INTERNAL_ERROR, e);
      }     
    }

    /** 
     * Blank Input constructor
     */        
    public BtcInput() {   
      prevHash = new byte[0];
      prevIndex = 0;
      script = new byte[0];
      sequence = new byte[0];
    }
    
    /** 
     * Serialize the input
     * @param output buffer to serialize the input to
     */
    public void serialize(ByteArrayOutputStream output) throws LedgerException {
      SerializeHelper.writeBuffer(output, prevHash);
      SerializeHelper.writeUint32LE(output, prevIndex);
      VarintUtils.write(output, script.length);
      SerializeHelper.writeBuffer(output, script);
      SerializeHelper.writeBuffer(output, sequence);
    }
    
    /**
     * Return the hash of the previous transaction
     * @return hash of the previous transaction
     */
    public byte[] getPrevHash() {
      return prevHash;
    }

    /**
     * Return the index in the previous transaction
     * @return index in the previous transaction
     */
    public long getPrevIndex() {
      return prevIndex;
    }

    /**
     * Return the serialized scriptSig
     * @return serialized scriptSig
     */    
    public byte[] getScript() {
      return script;
    }
    /**
     * Return the serialized sequence
     * @return serialized sequence
     */    
    public byte[] getSequence() {
      return sequence;
    }
    /**
     * Set the hash of the previous transaction
     * @param prevHash hash of the previous transaction
     */
    public void setPrevHash(byte[] prevHash) {
      this.prevHash = prevHash;
    }
    /**
     * Set the index in the previous transaction
     * @param prevIndex index in the previous transaction
     */
    public void setPrevIndex(long prevIndex) {
      this.prevIndex = prevIndex;
    }
    /**
     * Set the serialized script
     * @param script serialized script
     */
    public void setScript(byte[] script) {
      this.script = script;
    }
    /**
     * Set the serialized sequence
     * @param sequence serialized sequence
     */
    public void setSequence(byte[] sequence) {
      this.sequence = sequence;
    }
    
    public String toString() {
      StringBuffer buffer = new StringBuffer();
      buffer.append("Prevout ").append(Dump.dump(prevHash)).append(':').append(prevIndex).append('\r').append('\n');
      buffer.append("Script ").append(Dump.dump(script)).append('\r').append('\n');
      buffer.append("Sequence ").append(Dump.dump(sequence)).append('\r').append('\n');
      return buffer.toString();
    }   
  }

  /**
   * \brief Internal representation of a Bitcoin transaction output
  */    
  public class BtcOutput {

    /** Serialized amount */    
    private byte[] amount;
    /** Serialized scriptPubKey */
    private byte[] script;

    /** 
     * Output constructor from raw data
     * @param data serialized output data
     */        
    public BtcOutput(ByteArrayInputStream data) throws LedgerException {
      try {
        amount = new byte[8];
        data.read(amount);
        long scriptSize = VarintUtils.read(data);
        script = new byte[(int)scriptSize];
        data.read(script);        
      }
      catch(Exception e) {
        throw new LedgerException(LedgerException.ExceptionReason.INTERNAL_ERROR, e);
      }     
    }

    /** 
     * Blank Output constructor
     */            
    public BtcOutput() {
      amount = new byte[0];
      script = new byte[0];
    }

    /** 
     * Serialize the output
     * @param output buffer to serialize the output to
     */    
    public void serialize(ByteArrayOutputStream output) throws LedgerException {
      SerializeHelper.writeBuffer(output, amount);
      VarintUtils.write(output, script.length);
      SerializeHelper.writeBuffer(output, script);
    }   

    /**
     * Return the serialized amount
     * @return serialized amount
     */    
    public byte[] getAmount() {
      return amount;
    }
    /**
     * Return the serialized scriptPubKey
     * @return serialized scriptPubKey
     */    
    public byte[] getScript() {
      return script;
    }
    /**
     * Set the serialzied amount
     * @param amount serialized amount
     */    
    public void setAmount(byte[] amount) {
      this.amount = amount;
    }
    /**
     * Set the serialzied scriptPubKey
     * @param script serialized scriptPubKey
     */    
    public void setScript(byte[] script) {
      this.script = script;
    }
    
    public String toString() {
      StringBuffer buffer = new StringBuffer();
      buffer.append("Amount ").append(Dump.dump(amount)).append('\r').append('\n');
      buffer.append("Script ").append(Dump.dump(script)).append('\r').append('\n');
      return buffer.toString();     
    }
  }
  
  /** Serialized transction version */
  private byte[] version;
  /** Transaction inputs */
  private Vector<BtcInput> inputs;
  /** Transaction outputs */
  private Vector<BtcOutput> outputs;
  /** Serialized transasction lockTime */
  private byte[] lockTime;
  /** Serialized witness for Segwit transactions */
  private byte[] witness;

  private static final int BIP141_MARKER = 1;

  /** 
    * Transaction constructor from raw data
    * @param txData serialized transaction data
    */            
  public BtcTransaction(byte[] txData) throws LedgerException  {    
    ByteArrayInputStream data = new ByteArrayInputStream(txData);
    boolean segwit = false;
    inputs = new Vector<BtcInput>();
    outputs = new Vector<BtcOutput>();
    try {
      version = new byte[4];
      data.read(version);
      if ((txData[4] == 0) && (txData[5] != 0)) {
        if (txData[5] != BIP141_MARKER) {
          throw new LedgerException(LedgerException.ExceptionReason.INVALID_PARAMETER, "Unsupported transaction marker " + (txData[5] & 0xff));
        }
        segwit = true;
        data.skip(2);
      }
      long numberItems = VarintUtils.read(data);
      for (long i=0; i<numberItems; i++) {
        inputs.add(new BtcInput(data));
      }
      numberItems = VarintUtils.read(data);
      for (long i=0; i<numberItems; i++) {
        outputs.add(new BtcOutput(data));
      }
      if (segwit) {
        witness = new byte[data.available() - 4];
        data.read(witness);
      }
      lockTime = new byte[4];
      data.read(lockTime);      
    }
    catch(Exception e) {
      throw new LedgerException(LedgerException.ExceptionReason.INTERNAL_ERROR, e);
    }         
  }

  /**
   * Blank Transaction constructor
   */  
  public BtcTransaction() {
    version = new byte[0];
    inputs = new Vector<BtcInput>();
    outputs = new Vector<BtcOutput>();
    lockTime = new byte[0];
  }

  /** 
    * Serialize the transaction
    * @param skipOutputLockTime true to stop the serialization before the number of outputs
    * @param skipWitness true to serialize the transaction without its witness
    * @return serialized transaction
    */      
  public byte[] serialize(boolean skipOutputLockTime, boolean skipWitness) throws LedgerException {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    SerializeHelper.writeBuffer(output, version);
    if ((witness != null) && !skipWitness) {
      output.write(0);
      output.write(BIP141_MARKER);
    }
    VarintUtils.write(output, inputs.size());
    for (BtcInput input : inputs) {
      input.serialize(output);
    }
    if (!skipOutputLockTime) {
      VarintUtils.write(output, outputs.size());
      for (BtcOutput outputItem : outputs) {
        outputItem.serialize(output);
      }
      if ((witness != null) && !skipWitness) {
        SerializeHelper.writeBuffer(output, witness);
      }
      SerializeHelper.writeBuffer(output, lockTime);
    }
    return output.toByteArray();
  } 

  /** 
    * Serialize the transaction outputs (including the number of outputs)
    * @return serialized outputs
    */      
  public byte[] serializeOutputs() throws LedgerException {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    VarintUtils.write(output, outputs.size());
    for (BtcOutput outputItem : outputs) {
      outputItem.serialize(output);
    }
    return output.toByteArray();
  }

  /**
   * Return the serialized version
   * @return serialized version
   */
  public byte[] getVersion() {
    return version;
  }
  /** 
   * Return the list of inputs
   * @return list of inputs
   */
  public Vector<BtcInput> getInputs() {
    return inputs;
  }
  /**
   * Return the list of outputs
   * @return list of outputs
   */
  public Vector<BtcOutput> getOutputs() {
    return outputs;
  }
  /**
   * Return the serialized lockTime
   * @return serialized lockTime
   */
  public byte[] getLockTime() {
    return lockTime;
  }

  /**
   * Return the serialized witness
   * @return serialized witness
   */
  public byte[] getWitness() {
    return witness;
  }
  
  /**
   * Set the serialized transaction version
   * @param version serialized transaction version
   */
  public void setVersion(byte[] version) {
    this.version = version;
  }
  /**
   * Add an input to the transaction
   * @param input input to add 
   */
  public void addInput(BtcInput input) {
    this.inputs.add(input);
  }
  /**
   * Add an output to the transaction
   * @param output output to add 
   */
  public void addOutput(BtcOutput output) {
    this.outputs.add(output);
  }
  /**
   * Set the serialized lockTime
   * @param lockTime serialized lockTime
   */
  public void setLockTime(byte[] lockTime) {
    this.lockTime = lockTime;
  }
  /**
   * Set the serialized witness
   * @param witness serialized witness
   */
  public void setWitness(byte[] witness) {
    this.witness = witness;
  }
  
  public String toString() {
    StringBuffer buffer = new StringBuffer();
    buffer.append("Version ").append(Dump.dump(version)).append('\r').append('\n');
    int index = 1;
    for (BtcInput input : inputs) {
      buffer.append("Input #").append(index).append('\r').append('\n');
      buffer.append(input.toString());
      index++;
    }
    index = 1;
    for (BtcOutput output : outputs) {
      buffer.append("Output #").append(index).append('\r').append('\n');
      buffer.append(output.toString());
      index++;      
    }
    if (witness != null) {
      buffer.append("Witness ").append(Dump.dump(witness)).append('\r').append('\n');
    }
    buffer.append("LockTime ").append(Dump.dump(lockTime)).append('\r').append('\n');
    return buffer.toString();
  }

}
