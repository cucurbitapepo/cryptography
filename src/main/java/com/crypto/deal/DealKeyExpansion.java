package com.crypto.deal;

import com.crypto.cipher.keyexpansion.KeyExpansion;
import com.crypto.des.DesCipher;
import com.crypto.util.BitUtils;
import com.crypto.util.datatypes.Block;
import com.crypto.util.datatypes.Key;
import com.crypto.util.datatypes.RoundKey;

import static com.crypto.deal.config.DealConfig.fixedDesKey;
import static com.crypto.deal.config.DealConfig.fixedInitializationVector;

public class DealKeyExpansion implements KeyExpansion {

  @Override
  public RoundKey[] generateRoundKeys(Key key) {

    int rounds;
    int s;
    switch (key.getSize()) {
      case 16:
        rounds = 6;
        s = 2;
        break;
      case 24:
        rounds = 6;
        s = 3;
        break;
      case 32:
        rounds = 8;
        s = 4;
        break;
      default:
        throw new IllegalArgumentException(String.format("Key size must be 16 or 24 or 32 bytes (current size is %d)", key.getSize()));
    }
    RoundKey[] roundKeys = new RoundKey[rounds];

    byte[] previousBlock = fixedInitializationVector;
    byte[][] keyParts = splitKeyIntoBlocks(key.getData(), 8);
    DesCipher desCipher = new DesCipher();
    desCipher.setRoundKeys(new Key(fixedDesKey));

    for (int i = 0; i < s; i++) {
      byte[] xoredBlock = BitUtils.xor(previousBlock, keyParts[i]);
      Block encryptedBlock = desCipher.encryptBlock(new Block(xoredBlock));
      roundKeys[i] = new RoundKey(encryptedBlock.getData());
    }

    int constantShift = 1;
    byte[] constant = new byte[]{(byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};
    for (int i = s; i < rounds; i++) {
      constant = BitUtils.rotateLeft(constant, -(constantShift - 1), 0, 32);
      byte[] xoredBlock = BitUtils.xor(constant, keyParts[i % s]);
      xoredBlock = BitUtils.xor(xoredBlock, previousBlock);
      Block encryptedBlock = desCipher.encryptBlock(new Block(xoredBlock));
      roundKeys[i] = new RoundKey(encryptedBlock.getData());
      previousBlock = encryptedBlock.getData();
      constantShift <<= 1;
    }

    return roundKeys;
  }

  private byte[][] splitKeyIntoBlocks(byte[] key, int blockSize) {
    int numBlocks = (int) Math.ceil((double) key.length / blockSize);
    byte[][] blocks = new byte[numBlocks][blockSize];
    for (int i = 0; i < numBlocks; i++) {
      System.arraycopy(key, i * blockSize, blocks[i], 0, Math.min(blockSize, key.length - i * blockSize));
    }
    return blocks;
  }

}
