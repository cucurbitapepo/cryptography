package com.crypto.des;

import com.crypto.cipher.keyexpansion.KeyExpansion;
import com.crypto.util.BitPermutor;
import com.crypto.util.BitUtils;
import com.crypto.util.datatypes.Key;
import com.crypto.util.datatypes.RoundKey;

import java.util.Arrays;

import static com.crypto.des.config.DesConfiguration.*;

public class DesKeyExpansion implements KeyExpansion {

  @Override
  public RoundKey[] generateRoundKeys(Key key) {
    byte[] keyData = key.getData();
    if (keyData.length != 8) {
      throw new IllegalArgumentException("Key size must be 8");
    }
    byte[] permutedKeyBytes = BitPermutor.permuteBits(
            keyData,
            PC1,
            BitPermutor.BitOrder.MostSignificantToLeastSignificant,
            BitPermutor.StartingBitIndex.ONE
    );
    byte[] leftHalf = Arrays.copyOfRange(permutedKeyBytes, 0, 4);
    byte[] rightHalf = Arrays.copyOfRange(permutedKeyBytes, 3, 7);

    RoundKey[] roundKeys = new RoundKey[16];
    for (int i = 0; i < 16; i++) {
      leftHalf = BitUtils.rotateLeft(leftHalf, rotations[i], 0, 28);
      rightHalf = BitUtils.rotateLeft(rightHalf, rotations[i], 4, 28);
      byte[] combined = BitUtils.concatenate(leftHalf, 0, 28, rightHalf, 4, 28);
      combined = BitPermutor.permuteBits(
              combined,
              PC2,
              BitPermutor.BitOrder.MostSignificantToLeastSignificant,
              BitPermutor.StartingBitIndex.ONE
      );
      roundKeys[i] = new RoundKey(combined);
    }

    return roundKeys;
  }

}
