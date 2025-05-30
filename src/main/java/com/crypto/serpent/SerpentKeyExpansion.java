package com.crypto.serpent;

import com.crypto.cipher.keyexpansion.KeyExpansion;
import com.crypto.util.BitUtils;
import com.crypto.util.datatypes.Key;
import com.crypto.util.datatypes.RoundKey;

import static com.crypto.serpent.config.SerpentConfig.*;

public class SerpentKeyExpansion implements KeyExpansion {

  /**
   * generates 33 round keys 128 bit long each.
   */
  @Override
  public RoundKey[] generateRoundKeys(Key key) {

    byte[] keyData = key.getData();
    int[] paddedKey = new int[16];
    int offset = 0;
    int length = 0;

    for(offset = 0; offset + 4 < keyData.length; offset += 4) {
      paddedKey[length++] = BitUtils.littleEndianToInt(keyData, offset);
    }

    if(offset % 4 == 0) {
      paddedKey[length++] = BitUtils.littleEndianToInt(keyData, offset);
      if(length < 8) {
        paddedKey[length] = 1;
      }
    } else {
      throw new IllegalArgumentException("key must be a multiple of 4 bytes");
    }

    int[] w = new int[132];

    for(int i = 8; i < 16; i++) {
      paddedKey[i] = BitUtils.rotateLeft(paddedKey[i-8] ^ paddedKey[i-5] ^ paddedKey[i-3] ^ paddedKey[i-1] ^ goldenRatio ^ (i - 8), 11);
    }

    RoundKey[] roundKeys = new RoundKey[33];

    System.arraycopy(paddedKey, 8, w, 0, 8);

    for(int i = 8; i < 132; i++) {
      w[i] = BitUtils.rotateLeft(w[i-8] ^ w[i-5] ^ w[i-3] ^ w[i-1] ^ goldenRatio ^ i, 11);
    }

    int[] X;
    for(int roundKeyIndex = 0; roundKeyIndex < 33; roundKeyIndex++) {
      int sBlockIndex = (3 - (roundKeyIndex % 8) + 8) % 8;
      int wordSequence = roundKeyIndex * 4;

      X = applySBox(sBlockIndex, w[wordSequence], w[wordSequence + 1], w[wordSequence + 2], w[wordSequence + 3]);
      roundKeys[roundKeyIndex] = new RoundKey(BitUtils.intArrayToByteArray(X));
    }
    return roundKeys;
  }

}
