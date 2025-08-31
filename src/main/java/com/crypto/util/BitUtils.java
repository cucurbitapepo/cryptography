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

  public static byte[] shiftLeft(byte[] data, int shift, int startBit, int bitCount) {
    if (shift < 0) {
      throw new IllegalArgumentException("Shift value must be non-negative");
    }

    data = reverseArray(data);

    BitSet bits = BitSet.valueOf(data);
    int totalBits = data.length * 8;

    BitSet shifted = new BitSet(totalBits);

    int lowerBound = totalBits - bitCount - startBit;

    for (int i = 0; i < bitCount; i++) {
      int originalIndex = lowerBound + i;
      int shiftedIndex = originalIndex + shift;

      if (shiftedIndex < lowerBound + bitCount) {
        shifted.set(shiftedIndex, bits.get(originalIndex));
      }
    }

    byte[] result = new byte[(totalBits + 7) / 8];
    for (int i = 0; i < totalBits; i++) {
      if (shifted.get(i)) {
        result[i / 8] |= (byte) (1 << (i % 8));
      }
    }

    result = reverseArray(result);
    return result;
  }

  public static int rotateLeft(int x, int bits) {
    return (x << bits) | (x >>> -bits);
  }

  public static byte[] xor(byte[] a, byte[] b) {
    byte[] result = new byte[a.length];
    for (int i = 0; i < a.length; i++) {
      result[i] = (byte) (a[i] ^ b[i]);
    }
    return result;
  }

  /**
   * rearranges bytes in inverse order inside each 4-byte group
   */
  public static byte[] rearrangeBytes(byte[] input) {
    if (input.length != 16) {
      throw new IllegalArgumentException("Input array must have exactly 16 bytes");
    }

    byte[] output = new byte[16];

    for (int i = 0; i < 4; i++) {
      int groupStart = i * 4;
      output[groupStart] = input[groupStart + 3];
      output[groupStart + 1] = input[groupStart + 2];
      output[groupStart + 2] = input[groupStart + 1];
      output[groupStart + 3] = input[groupStart];
    }

    return output;
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

  public static byte[] concatenate(byte[][] data) {
    int totalLength = 0;
    for (byte[] array : data) {
      if (array != null) {
        totalLength += array.length;
      }
    }

    byte[] result = new byte[totalLength];
    int offset = 0;

    for (byte[] array : data) {
      if (array != null) {
        System.arraycopy(array, 0, result, offset, array.length);
        offset += array.length;
      }
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

  public static int[] byteArrayToIntArray(byte[] byteArray) {
    if (byteArray.length % 4 != 0) {
      throw new IllegalArgumentException("Input array length must be a multiple of 4");
    }
    int length = byteArray.length / 4;
    int[] intArray = new int[length];

    for (int i = 0; i < length; i++) {
      int offset = i * 4;
      intArray[i] = ((byteArray[offset] & 0xFF) << 24) |
                    ((byteArray[offset + 1] & 0xFF) << 16) |
                    ((byteArray[offset + 2] & 0xFF) << 8) |
                    (byteArray[offset + 3] & 0xFF);
    }

    return intArray;
  }

  public static int[] byteArrayToLittleEndianArray(byte[] byteArray) {
    if (byteArray.length % 4 != 0) {
      throw new IllegalArgumentException("Input array length must be a multiple of 4");
    }
    int length = byteArray.length / 4;
    int[] intArray = new int[length];

    for (int i = 0; i < length; i++) {
      int offset = i * 4;
      intArray[i] = ((byteArray[offset] & 0xFF)) |
                    ((byteArray[offset + 1] & 0xFF) << 8) |
                    ((byteArray[offset + 2] & 0xFF) << 16) |
                    ((byteArray[offset + 3] & 0xFF) << 24);
    }

    return intArray;
  }

  public static byte[] intArrayToByteArray(int[] ints) {
    byte[] byteArray = new byte[ints.length * 4];
    for (int i = 0; i < ints.length; i++) {
      byteArray[i * 4] = (byte) (ints[i] >> 24);
      byteArray[i * 4 + 1] = (byte) (ints[i] >> 16);
      byteArray[i * 4 + 2] = (byte) (ints[i] >> 8);
      byteArray[i * 4 + 3] = (byte) (ints[i]);
    }
    return byteArray;
  }
  public static byte[] littleEndianArrayToByteArray(int[] ints) {
    byte[] byteArray = new byte[ints.length * 4];
    for (int i = 0; i < ints.length; i++) {
      byteArray[i * 4] = (byte) (ints[i]);
      byteArray[i * 4 + 1] = (byte) (ints[i] >> 8);
      byteArray[i * 4 + 2] = (byte) (ints[i] >> 16);
      byteArray[i * 4 + 3] = (byte) (ints[i] >> 24);
    }
    return byteArray;
  }

  public static byte[] intToByteArray(int value) {
    return new byte[]{
            (byte) ((value >> 24) & 0xFF),
            (byte) ((value >> 16) & 0xFF),
            (byte) ((value >> 8) & 0xFF),
            (byte) (value & 0xFF)
    };
  }

  public static byte[] littleEndianToByteArray(int value) {
    return new byte[]{
            (byte) (value & 0xFF),
            (byte) ((value >> 8) & 0xFF),
            (byte) ((value >> 16) & 0xFF),
            (byte) ((value >> 24) & 0xFF)
    };
  }

  public static int littleEndianToInt(byte[] bs, int off) {
    int n = bs[off] & 0xff;
    n |= (bs[++off] & 0xff) << 8;
    n |= (bs[++off] & 0xff) << 16;
    n |= bs[++off] << 24;
    return n;
  }
}
