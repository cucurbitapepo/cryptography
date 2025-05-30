package com.crypto.cipher;

import com.crypto.cipher.keyexpansion.KeyExpansion;
import com.crypto.util.datatypes.Block;
import com.crypto.util.datatypes.Key;
import com.crypto.util.datatypes.RoundKey;
import lombok.Getter;

public abstract class SubstitutionPermutationNetwork implements SymmetricCipher{

  public enum Operation {
    ENCRYPTION, DECRYPTION
  }

  private final KeyExpansion keyExpansion;
  @Getter
  private RoundKey[] roundKeys;
  private final int rounds;
  private final int blockSize;

  @Override
  public int getBlockSize() {
    return blockSize;
  }

  protected SubstitutionPermutationNetwork(KeyExpansion keyExpansion, int rounds, int blockSize) {
    this.keyExpansion = keyExpansion;
    this.rounds = rounds;
    this.blockSize = blockSize;
  }


  @Override
  public Block encryptBlock(Block block) {
    return performRounds(block, Operation.ENCRYPTION);
  }

  @Override
  public Block decryptBlock(Block block) {
    return performRounds(block, Operation.DECRYPTION);
  }

  @Override
  public void setRoundKeys(Key key) {
    this.roundKeys = keyExpansion.generateRoundKeys(key);
  }

  private Block performRounds(Block block, Operation operation) {
    return switch (operation) {
      case ENCRYPTION -> performEncryptionRounds(block);
      case DECRYPTION -> performDecryptionRounds(block);
    };
  }

  private Block performEncryptionRounds(Block block) {
    if(roundKeys == null) {
      throw new IllegalStateException("Round keys not set");
    }
    byte[] data = block.getData();
    if(data.length != blockSize) {
      throw new IllegalArgumentException("Given block size does not match block size defined in constructor");
    }


    for(int i = 0; i < rounds; i++) {
      RoundKey roundKey = (roundKeys[i]);
      data = applyEncryptionRound(data, i, roundKey);
    }

    return new Block(data);
  }

  private Block performDecryptionRounds(Block block) {
    if(roundKeys == null) {
      throw new IllegalStateException("Round keys not set");
    }
    byte[] data = block.getData();
    if(data.length != blockSize) {
      throw new IllegalArgumentException("Given block size does not match block size defined in constructor");
    }

    for(int i = rounds - 1; i >= 0; i--) {
      RoundKey roundKey = (roundKeys[i]);
      data = applyDecryptionRound(data, i, roundKey);
    }

    return new Block(data);
  }

  protected byte[] applyEncryptionRound(byte[] data, int roundIndex, RoundKey roundKey) {
    data = applyKey(data, roundKey);
    data = substitute(data, roundIndex, Operation.ENCRYPTION);
    data = permute(data, Operation.ENCRYPTION);
    return data;
  }

  protected byte[] applyDecryptionRound(byte[] data, int roundIndex, RoundKey roundKey) {
    data = permute(data, Operation.DECRYPTION);
    data = substitute(data, roundIndex, Operation.DECRYPTION);
    data = applyKey(data, roundKey);
    return data;
  }

  protected abstract byte[] substitute(byte[] data, int roundIndex, Operation operation);
  protected abstract byte[] permute(byte[] data, Operation operation);
  protected abstract byte[] applyKey(byte[] data, RoundKey roundKey);

}
