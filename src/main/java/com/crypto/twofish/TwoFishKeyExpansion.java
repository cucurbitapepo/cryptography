package com.crypto.twofish;

import com.crypto.cipher.keyexpansion.KeyExpansion;
import com.crypto.twofish.config.TwoFishConfig;
import com.crypto.util.BitUtils;
import com.crypto.util.datatypes.Key;
import com.crypto.util.datatypes.RoundKey;

import java.util.HexFormat;

public class TwoFishKeyExpansion implements KeyExpansion {

  @Override
  public RoundKey[] generateRoundKeys(Key key) {


    byte[] keyBytes = key.getData();
    if (!isValidKeySize(keyBytes.length)) {
      throw new IllegalArgumentException("Invalid key size: " + keyBytes.length + " bytes");
    }

    int[] M = BitUtils.byteArrayToLittleEndianArray(keyBytes); // little-endian
    int[] ME = extractEvenWords(M);
    int[] MO = extractOddWords(M);

    RoundKey[] roundKeys = new RoundKey[TwoFishConfig.TOTAL_ROUND_KEYS];

    for (int i = 0; i < 20; i++) {
      int A = TwoFishUtils.h(2 * i * TwoFishConfig.RHO, ME, TwoFishConfig.GF_256_FDBK);
      int B = TwoFishUtils.h((2 * i + 1) * TwoFishConfig.RHO, MO, TwoFishConfig.GF_256_FDBK);
      B = TwoFishUtils.ROL(B, 8);

      roundKeys[i * 2] = new RoundKey(BitUtils.intToByteArray(A + B));
      roundKeys[i * 2 + 1] = new RoundKey(BitUtils.intToByteArray((TwoFishUtils.ROL(A + 2 * B, 9))));
    }

    return roundKeys;
  }

  private boolean isValidKeySize(int length) {
    for (int size : TwoFishConfig.VALID_KEY_SIZES) {
      if (length == size) return true;
    }
    return false;
  }

  private int[] extractEvenWords(int[] M) {
    int[] M_E = new int[M.length / 2 + M.length % 2];
    int index = 0;
    for (int j = 0; j < M.length; j +=2) {
      M_E[index++] = M[j];
    }
    return M_E;
  }

  private int[] extractOddWords(int[] M) {
    int[] M_O = new int[M.length / 2];
    int index = 0;
    for (int j = 1; j < M.length; j +=2) {
      M_O[index++] = M[j];
    }
    return M_O;
  }

}
