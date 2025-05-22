package com.crypto.des;

import com.crypto.cipher.transformation.CipherTransformation;
import com.crypto.util.BitPermutor;
import com.crypto.util.BitUtils;
import com.crypto.util.datatypes.Block;
import com.crypto.util.datatypes.RoundKey;

import static com.crypto.des.config.DesConfiguration.*;

public class DesCipherTransformation implements CipherTransformation {

  @Override
  public Block transform(Block block, RoundKey roundKey) {
    byte[] blockData = block.getData();
    byte[] roundKeyData = roundKey.getData();
    if (blockData.length != 4 || roundKeyData.length != 6) {
      throw new IllegalArgumentException("Invalid data or key length in Feistel F function");
    }

    blockData = BitPermutor.permuteBits(
            blockData,
            E,
            BitPermutor.BitOrder.MostSignificantToLeastSignificant,
            BitPermutor.StartingBitIndex.ONE
    );

    blockData = BitUtils.xor(blockData, roundKeyData);

    byte[] substitutedData = new byte[4];
    for (int i = 0; i < 8; i++) {
      int sixBits = extractSixBits(blockData, i * 6, (i + 1) * 6);

      int row = (((sixBits >>> 5) & 0x1) << 1) | (sixBits & 0x1);
      int col = (sixBits >>> 1) & 0xF;

      int sBoxValue = S[i][row * 16 + col];

      substituteFourBits(substitutedData, sBoxValue, i * 4);
    }

    byte[] permutedData = BitPermutor.permuteBits(
            substitutedData,
            P,
            BitPermutor.BitOrder.MostSignificantToLeastSignificant,
            BitPermutor.StartingBitIndex.ONE
    );

    return new Block(permutedData);
  }

  private int extractSixBits(byte[] data, int start, int end) {
    int result = 0;
    for (int i = start; i < end; i++) {
      int byteIndex = i / 8;
      int bitIndex = i % 8;
      boolean bit = ((data[byteIndex] >> (7 - bitIndex)) & 0x1) == 1;
      result = (result << 1) | (bit ? 1 : 0);
    }
    return result;
  }

  private void substituteFourBits(byte[] data, int value, int bitOffset) {
    for (int i = 0; i < 4; i++) {
      int byteIndex = (bitOffset + i) / 8;
      int bitIndex = (bitOffset + i) % 8;
      boolean bit = ((value >>> (3 - i)) & 0x1) == 1;
      data[byteIndex] = (byte) (data[byteIndex] & ~(1 << (7 - bitIndex)));
      data[byteIndex] = (byte) ((data[byteIndex] & 0xFF) | ((bit ? 1 : 0) << (7 - bitIndex)));
    }
  }

}
