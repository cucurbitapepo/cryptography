package com.crypto.cipher;

import com.crypto.cipher.keyexpansion.KeyExpansion;
import com.crypto.cipher.transformation.CipherTransformation;
import com.crypto.util.datatypes.Block;
import com.crypto.util.datatypes.Key;
import com.crypto.util.datatypes.RoundKey;

import java.util.Arrays;

public class FeistelNetwork implements SymmetricCipher {

  public enum Operation {
    ENCRYPTION, DECRYPTION
  }

  private final CipherTransformation cipherTransformation;
  private final KeyExpansion keyExpansion;
  private RoundKey[] roundKeys;

  public FeistelNetwork(CipherTransformation cipherTransformation, KeyExpansion keyExpansion) {
    this.cipherTransformation = cipherTransformation;
    this.keyExpansion = keyExpansion;
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

  private Block performRounds(Block dataBlock, Operation operation) {
    byte[] data = dataBlock.getData();
    int blockSize = data.length;
    if (blockSize % 2 != 0) {
      throw new IllegalArgumentException("Block size must be even");
    }

    int halfSize = blockSize / 2;
    Block leftHalf = new Block(Arrays.copyOfRange(data, 0, halfSize));
    Block rightHalf = new Block(Arrays.copyOfRange(data, halfSize, blockSize));

    int rounds = roundKeys.length;
    for (int i = 0; i < rounds; i++) {
      Block tmp = new Block(rightHalf.getData());
      RoundKey roundKey = (operation.equals(Operation.ENCRYPTION) ? roundKeys[i] : roundKeys[rounds - i - 1]);
      rightHalf = xor(leftHalf, cipherTransformation.transform(rightHalf, roundKey));
      leftHalf = new Block(tmp.getData());
    }

    byte[] result = new byte[blockSize];
    System.arraycopy(rightHalf.getData(), 0, result, 0, halfSize);
    System.arraycopy(leftHalf.getData(), 0, result, halfSize, halfSize);

    return new Block(result);
  }

  private Block xor(Block a, Block b) {
    byte[] result = new byte[a.getData().length];
    for (int i = 0; i < result.length; i++) {
      result[i] = (byte) (a.getData()[i] ^ b.getData()[i]);
    }
    return new Block(result);
  }
}
