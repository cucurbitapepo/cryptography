package com.crypto.twofish;

import com.crypto.cipher.transformation.CipherTransformation;
import com.crypto.twofish.config.TwoFishConfig;
import com.crypto.util.BitUtils;
import com.crypto.util.datatypes.Block;
import com.crypto.util.datatypes.RoundKey;

import static com.crypto.twofish.TwoFishUtils.h;

public class TwoFishCipherTransformation implements CipherTransformation {
  @Override
  public Block transform(Block block, RoundKey roundKey) {
    int[] roundKeys = BitUtils.byteArrayToIntArray(roundKey.getData());
    return new Block(performEncryptionConversion(block.getData(), roundKeys[0], roundKeys[1], TwoFishCipher.S));
  }

  public byte[] performEncryptionConversion(byte[] bytes, int roundKey1, int roundKey2, int[] S) {
    int R0 = (bytes[0] & 0xFF) | ((bytes[1] & 0xFF) << 8) | ((bytes[2] & 0xFF) << 16) | ((bytes[3] & 0xFF) << 24);
    int R1 = (bytes[4] & 0xFF) | ((bytes[5] & 0xFF) << 8) | ((bytes[6] & 0xFF) << 16) | ((bytes[7] & 0xFF) << 24);
    int T0 = h(R0, S, TwoFishConfig.GF_256_FDBK);
    int T1 = h(TwoFishUtils.ROL(R1, 8), S, TwoFishConfig.GF_256_FDBK);

    int F0 = (T0 + T1 + roundKey1);
    int F1 = (T0 + 2 * T1 + roundKey2);

    byte[] out = new byte[8];
    for (int i = 0; i < 4; i++) {
      out[i] = (byte) (F0 >>> (8 * i));
      out[4 + i] = (byte) (F1 >>> (8 * i));
    }
    return out;
  }

}
