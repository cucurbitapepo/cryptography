package com.crypto.util;

import java.util.BitSet;

public class BitPermutor {

  public enum BitOrder {
    LeastSignificantToMostSignificant,
    MostSignificantToLeastSignificant
  }

  public enum StartingBitIndex {
    ZERO(0),
    ONE(1);

    private final int bitIndex;

    StartingBitIndex(int bitIndex) {
      this.bitIndex = bitIndex;
    }

    private int getValue() {
      return bitIndex;
    }
  }

  public static byte[] permuteBits(byte[] input, int[] permutation, BitOrder bitOrder, StartingBitIndex startingBitIndex) {

    input = BitUtils.reverseArray(input);
    BitSet inputBits = BitSet.valueOf(input);
    int totalBits = input.length * 8;

    BitSet outputBits = new BitSet(permutation.length);
    int correctingShift = (8 - (permutation.length % 8)) % 8;
    try {
      for (int i = 0; i < permutation.length; i++) {
        int index = permutation[i];

        index -= startingBitIndex.getValue();

        int bitIndex;
        if (bitOrder == BitOrder.LeastSignificantToMostSignificant) {
          bitIndex = index;
        } else {
          bitIndex = totalBits - 1 - index;
        }

        boolean isBitSet = inputBits.get(bitIndex);

        outputBits.set(i + correctingShift, isBitSet);
      }
    } catch (Exception e) {
      throw new IllegalArgumentException("Error occurred upon performing permutation. Make sure your parameters are valid.");
    }

    byte[] result = new byte[(permutation.length + 7) / 8];
    for (int i = 0; i < permutation.length; i++) {
      if (outputBits.get(i + correctingShift)) {
        result[i / 8] |= (byte) (1 << (7 - (i + correctingShift) % 8));
      }
    }

    return result;
  }

}
