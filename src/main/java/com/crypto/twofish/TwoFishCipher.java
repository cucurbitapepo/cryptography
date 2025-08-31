package com.crypto.twofish;

import com.crypto.cipher.FeistelNetwork;
import com.crypto.twofish.config.TwoFishConfig;
import com.crypto.util.BitUtils;
import com.crypto.util.datatypes.Block;
import com.crypto.util.datatypes.Key;
import com.crypto.util.datatypes.RoundKey;

import java.util.Arrays;

public class TwoFishCipher extends FeistelNetwork {

  public static int[] S;

  public TwoFishCipher() {
    super(new TwoFishCipherTransformation(), new TwoFishKeyExpansion());
  }

  @Override
  public Block encryptBlock(Block block) {
    int[] data = BitUtils.byteArrayToLittleEndianArray(block.getData());

    whitenData(data, 0);

    for(int i = 0; i < 16; i++) {
      int[] F = BitUtils.byteArrayToLittleEndianArray(
              this.cipherTransformation.transform(
              new Block(BitUtils.littleEndianArrayToByteArray(new int[]{data[0], data[1]})),
              new RoundKey(BitUtils.concatenate(new byte[][]{this.roundKeys[2 * i + 8].getData(), this.roundKeys[2 * i + 8 + 1].getData()}))
      ).getData());

      data[2] = TwoFishUtils.ROR(data[2] ^ F[0], 1);
      data[3] = TwoFishUtils.ROL(data[3], 1) ^ F[1];

      if(i != 15) {
        int tmp0 = data[0];
        int tmp1 = data[1];
        data[0] = data[2];
        data[1] = data[3];
        data[2] = tmp0;
        data[3] = tmp1;
      }
    }

    whitenData(data, 4);
    return new Block(BitUtils.littleEndianArrayToByteArray(data));
  }

  @Override
  public Block decryptBlock(Block block) {
    int[] data = BitUtils.byteArrayToLittleEndianArray(block.getData());

    whitenData(data, 4);

    for(int i = 15; i >= 0; i--) {
      if(i != 15) {
        int tmp0 = data[0];
        int tmp1 = data[1];
        data[0] = data[2];
        data[1] = data[3];
        data[2] = tmp0;
        data[3] = tmp1;
      }
      int[] F = BitUtils.byteArrayToLittleEndianArray(
              this.cipherTransformation.transform(
                      new Block(BitUtils.littleEndianArrayToByteArray(new int[]{data[0], data[1]})),
                      new RoundKey(BitUtils.concatenate(new byte[][]{this.roundKeys[2 * i + 8].getData(), this.roundKeys[2 * i + 8 + 1].getData()}))
              ).getData());

      data[2] = TwoFishUtils.ROL(data[2], 1) ^ F[0];
      data[3] = TwoFishUtils.ROR(data[3] ^ F[1], 1);

    }

    whitenData(data, 0);
    return new Block(BitUtils.littleEndianArrayToByteArray(data));
  }

  @Override
  public void setRoundKeys(Key key) {
    super.setRoundKeys(key);
    this.S = generateSBlocks(BitUtils.byteArrayToLittleEndianArray(key.getData()));
  }

  public void whitenData(int[] data, int roundKeyIndexFirst) {
    for (int i = 0; i < 4; i++) {
      data[i] ^= BitUtils.byteArrayToIntArray(this.roundKeys[i + roundKeyIndexFirst].getData())[0];
    }
  }

  private int[] generateSBlocks(int[] M) {
    int k = M.length;
    byte[] keyBytes = new byte[k * 4];

    for (int i = 0; i < k; i++) {
      keyBytes[4 * i] = (byte) (M[i] & 0xFF);
      keyBytes[4 * i + 1] = (byte) ((M[i] >> 8) & 0xFF);
      keyBytes[4 * i + 2] = (byte) ((M[i] >> 16) & 0xFF);
      keyBytes[4 * i + 3] = (byte) ((M[i] >> 24) & 0xFF);
    }

    int[] S = new int[k / 2];
    for (int i = 0; i < (k / 2); i++) {
      byte[] block = Arrays.copyOfRange(keyBytes, 8 * i, Math.min(8 * i + 8, keyBytes.length));

      int[] s_i = new int[4];
      for (int row = 0; row < 4; row++) {
        for (int col = 0; col < block.length; col++) {
          s_i[row] ^= TwoFishUtils.multiplyInGF256(TwoFishConfig.RS[row][col], block[col] & 0xFF, TwoFishConfig.RS_GF_FDBK);
        }
      }

      S[(k / 2) - 1 - i] = (s_i[0] & 0xFF) | ((s_i[1] & 0xFF) << 8) |
                           ((s_i[2] & 0xFF) << 16) | (((s_i[3] & 0xFF) << 24));
    }
    return S;
  }

  @Override
  public int getBlockSize() {
    return 16;
  }
}
