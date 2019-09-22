package com.lathrum.USBBFS;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

public class Block {

  private int index;
  private long timestamp;
  private String hash;
  private String previousHash;
  private String name;
  private String data;
  private int nonce;
	
  public Block(int index, long timestamp, String previousHash, String name, String data) {
    this.index = index;
    this.timestamp = timestamp;
    this.previousHash = previousHash;
    this.name = name;
    this.data = data;
    nonce = 0;
    hash = Block.calculateHash(this);
  }

  public int getIndex() {
    return index;
  }

  public long getTimestamp() {
    return timestamp;
  }

  public String getHash() {
    return hash;
  }

  public String getPreviousHash() {
    return previousHash;
  }

  public String getName() {
    return name;
  }

  public String getData() {
    return data;
  }

  public String str() {
    return index + timestamp + previousHash + name + data + nonce;
  }

  public String toString() {
    StringBuilder builder = new StringBuilder();
    builder.append("Block #").append(index).append(" [previousHash : ").append(previousHash).append(", ").
    append("timestamp : ").append(new Date(timestamp)).append(", ").append("name : ").append(name).append(", ").
    append("data : ").append(data).append(", ").append("hash : ").append(hash).append("]");
    return builder.toString();
  }
	
  public static String calculateHash(Block block) {
    if (block != null) {
      MessageDigest digest = null;

      try {
        digest = MessageDigest.getInstance("SHA-256");
      } catch (NoSuchAlgorithmException e) {
        return null;
      }
			
      String txt = block.str();
      final byte bytes[] = digest.digest(txt.getBytes());
      final StringBuilder builder = new StringBuilder();
			
      for (final byte b : bytes) {
        String hex = Integer.toHexString(0xff & b);

        if (hex.length() == 1) {
          builder.append('0');
        }
				
        builder.append(hex);
      }
			
      return builder.toString();
    }
    
    return null;
  }

  public void mineBlock(int difficulty) {
      nonce = 0;
		
    while (!getHash().substring(0,  difficulty).equals(String.format("%0" + difficulty + "d", 0))) {
      nonce++;
      hash = Block.calculateHash(this);
    }
  }
}