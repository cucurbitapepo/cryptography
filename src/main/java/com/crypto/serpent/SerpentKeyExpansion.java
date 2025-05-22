package com.crypto.serpent;

import com.crypto.cipher.keyexpansion.KeyExpansion;
import com.crypto.util.BitUtils;
import com.crypto.util.datatypes.Key;
import com.crypto.util.datatypes.RoundKey;

import static com.crypto.serpent.config.SerpentConfig.S;
import static com.crypto.serpent.config.SerpentConfig.goldenRatio;

public class SerpentKeyExpansion implements KeyExpansion {

  /**
   * generates 33 round keys 128 bit long each.
   */
  @Override
  public RoundKey[] generateRoundKeys(Key key) {
    key = new Key(applyKeyPadding(key));
    byte[][] preRoundKeys = generatePreRoundKeys(key);
    return generateRoundKeys(preRoundKeys);
  }

  private byte[] applyKeyPadding(Key key) {
    byte[] paddedKey = new byte[32];
    byte[] keyData = key.getData();
    System.arraycopy(keyData, 0, paddedKey, 0, keyData.length);
    if (keyData.length != 32) {
      paddedKey[keyData.length] = (byte) 0x80;
    }

    return paddedKey;
  }

  private byte[][] generatePreRoundKeys(Key key) {
    byte[][] w = new byte[132][4]; // 33 подключа k_i по 4 int

    for(int i = 0; i < 8; i++) {
      System.arraycopy(key.getData(), i*4, w[i], 0, 4);
    }
    for (int i = 8; i < 132; i++) {
      byte[] offsetBytes = BitUtils.intToByteArray(i - 8);

      w[i] = BitUtils.rotateLeft(BitUtils.xor(w[i - 8],
              BitUtils.xor(w[i - 5],
                      BitUtils.xor(w[i - 3],
                              BitUtils.xor(
                                      w[i - 1],
                                      BitUtils.xor(goldenRatio, offsetBytes)
                              )
                      )
              )
      ), 11, 0, 32);
    }

    return w;
  }

  private RoundKey[] generateRoundKeys(byte[][] preRoundKeys) {
    RoundKey[] roundKeys = new RoundKey[33];
    for (int roundKeyIndex = 0; roundKeyIndex < 33; roundKeyIndex++) {
      int sBlockIndex = (3 - (roundKeyIndex % 8) + 8) % 8;

      byte[][] k = new byte[4][4];
      for(int wordIndex = 0; wordIndex < 4; wordIndex++) {
        k[wordIndex] = applySBox(preRoundKeys[4 * roundKeyIndex + wordIndex], sBlockIndex);
      }
      roundKeys[roundKeyIndex] = new RoundKey(BitUtils.concatenate(k));
    }

    return roundKeys;
  }

  private byte[] applySBox(byte[] block, int sBlockIndex) {
    byte[] result = new byte[4];
    for(int i = 0; i < 8; i++) {
      byte currentByte = block[i / 2];
      int shiftInsideByte = (i % 2 * 4);
      result[i/2] |= (byte) (S[sBlockIndex][((currentByte & 0xFF & (0x0F << shiftInsideByte)) >> shiftInsideByte)] << shiftInsideByte);
    }

    return result;
  }

}
