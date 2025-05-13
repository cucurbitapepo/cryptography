package com.crypto.util;

import java.util.BitSet;

public class BitUtils {

  public static byte[] reverseArray(byte[] input) {
    byte[] reversed = new byte[input.length];
    for (int i = 0; i < input.length; i++) {
      reversed[i] = input[input.length - 1 - i];
    }
    return reversed;
  }

  /**
   * Performs `rotation` bits left rotation within the given bit slice boundaries.
   * Use negative `rotation` data to rotate right with same logic.
   *
   * @param data     byte array to rotate
   * @param rotation length of rotation
   * @param startBit left inclusive bound of the bit slice in big-endian indexing, starting with index 0
   * @param bitCount amount of bits in chosen bit slice
   *
   *                 <p><b>Example:</b></p>
   *                 <pre>{@code
   *                 int rotation = 1;
   *                 int startBit = 2;
   *                 int bitCount = 6;
   *                 byte[] data = new byte[] {(byte) 0b00111100, (byte) 0b00000010};
   *
   *                 byte[] rotatedData = rotateLeft(data, rotation, startBit, bitCount);
   *                 //rotatedData now has 2 bytes: 0x00111001, 0x00000010
   *                 }</pre>
   */
  public static byte[] rotateLeft(byte[] data, int rotation, int startBit, int bitCount) {

    if (rotation < 0) {
      rotation = bitCount + (rotation % bitCount);
    }

    data = reverseArray(data);
    BitSet bits = BitSet.valueOf(data);
    int totalBits = data.length * 8;
    BitSet rotated = new BitSet(totalBits);

    for (int i = 0; i < totalBits; i++) {
      rotated.set(i, bits.get(i));
    }

    int lowerBound = totalBits - bitCount - startBit;

    for (int i = 0; i < bitCount; i++) {
      int originalIndex = lowerBound + (i % bitCount);
      int rotatedIndex = lowerBound + ((i + rotation) % bitCount);
      rotated.set(rotatedIndex, bits.get(originalIndex));
    }

    byte[] result = new byte[(totalBits + 7) / 8];
    for (int i = 0; i < totalBits; i++) {
      if (rotated.get(i)) {
        result[i / 8] |= (byte) (1 << (i % 8));
      }
    }
    result = reverseArray(result);
    return result;
  }

  public static byte[] xor(byte[] a, byte[] b) {
    byte[] result = new byte[a.length];
    for (int i = 0; i < a.length; i++) {
      result[i] = (byte) (a[i] ^ b[i]);
    }
    return result;
  }

  /**
   * Конкатенирует части двух массивов байтов в один массив байтов.
   *
   * @param array1  Первый массив байтов.
   * @param start1  Начальная позиция (в битах) в первом массиве.
   * @param length1 Количество битов, которые нужно взять из первого массива.
   * @param array2  Второй массив байтов.
   * @param start2  Начальная позиция (в битах) во втором массиве.
   * @param length2 Количество битов, которые нужно взять из второго массива.
   * @return Результирующий массив байтов.
   */
  public static byte[] concatenate(
          byte[] array1, int start1, int length1,
          byte[] array2, int start2, int length2) {

    int totalBits = length1 + length2;
    byte[] result = new byte[(totalBits + 7) / 8];
    int bitIndex = 0;

    for (int i = 0; i < length1; i++) {
      int byteIndex = (start1 + i) / 8;
      int bitPosition = (start1 + i) % 8;
      boolean bit = ((array1[byteIndex] >> (7 - bitPosition)) & 0x1) == 1;
      setBit(result, bitIndex++, bit);
    }

    for (int i = 0; i < length2; i++) {
      int byteIndex = (start2 + i) / 8;
      int bitPosition = (start2 + i) % 8;
      boolean bit = ((array2[byteIndex] >> (7 - bitPosition)) & 0x1) == 1;
      setBit(result, bitIndex++, bit);
    }

    return result;
  }

  /**
   * Устанавливает значение бита в указанной позиции в массиве байтов.
   *
   * @param array    Массив байтов.
   * @param bitIndex Индекс бита (от 0).
   * @param value    Значение бита (true или false).
   */
  private static void setBit(byte[] array, int bitIndex, boolean value) {
    int byteIndex = bitIndex / 8;
    int bitPosition = bitIndex % 8;
    if (value) {
      array[byteIndex] |= (byte) (1 << (7 - bitPosition));
    } else {
      array[byteIndex] &= (byte) ~(1 << (7 - bitPosition));
    }
  }
}
