package com.crypto.twofish;

import com.crypto.twofish.config.TwoFishConfig;

public class TwoFishUtils {

  public TwoFishUtils() {
  }

  /**
   * @param x    входное 32-битное слово
   * @param L    массив(для ключа M_O или M_E, для g используются S-Box)
   * @param mask маска для умножения в GF(2^8)
   */
  public static int h(int x, int[] L, int mask) {
    byte[] y = new byte[4];
    y[0] = (byte) (x & 0xFF);
    y[1] = (byte) ((x >> 8) & 0xFF);
    y[2] = (byte) ((x >> 16) & 0xFF);
    y[3] = (byte) ((x >> 24) & 0xFF);

    int k = L.length;
    if (k >= 4) {
      y[0] = (byte) (q1(y[0]) ^ ((L[3] >> 24) & 0xFF));
      y[1] = (byte) (q0(y[1]) ^ ((L[3] >> 16) & 0xFF));
      y[2] = (byte) (q0(y[2]) ^ ((L[3] >> 8) & 0xFF));
      y[3] = (byte) (q1(y[3]) ^ (L[3] & 0xFF));
    }

    if (k >= 3) {
      y[0] = (byte) (q1(y[0]) ^ ((L[2] >> 24) & 0xFF));
      y[1] = (byte) (q1(y[1]) ^ ((L[2] >> 16) & 0xFF));
      y[2] = (byte) (q0(y[2]) ^ ((L[2] >> 8) & 0xFF));
      y[3] = (byte) (q0(y[3]) ^ (L[2] & 0xFF));
    }

    y[0] = q1((byte) (q0((byte) (q0(y[0]) ^ ((L[1] >> 24) & 0xFF))) ^ ((L[0] >> 24) & 0xFF)));
    y[1] = q0((byte) (q0((byte) (q1(y[1]) ^ ((L[1] >> 16) & 0xFF))) ^ ((L[0] >> 16) & 0xFF)));
    y[2] = q1((byte) (q1((byte) (q0(y[2]) ^ ((L[1] >> 8) & 0xFF))) ^ ((L[0] >> 8) & 0xFF)));
    y[3] = q0((byte) (q1((byte) (q1(y[3]) ^ (L[1] & 0xFF))) ^ (L[0] & 0xFF)));

    return multiplyWithMds(y, mask);
  }

  public static byte q0(byte x) {
    return substituteWithQ(
            x,
            TwoFishConfig.q0_t0,
            TwoFishConfig.q0_t1,
            TwoFishConfig.q0_t2,
            TwoFishConfig.q0_t3
    );
  }

  public static byte q1(byte x) {
    return substituteWithQ(
            x,
            TwoFishConfig.q1_t0,
            TwoFishConfig.q1_t1,
            TwoFishConfig.q1_t2,
            TwoFishConfig.q1_t3
    );
  }

  private static byte substituteWithQ(byte x, byte[] t0, byte[] t1, byte[] t2, byte[] t3) {
    int a0 = (x >>> 4) & 0xF;
    int b0 = x & 0xF;

    int a1 = a0 ^ b0;
    int b1 = a0 ^ ror4(b0, 1) ^ ((8 * a0) & 0xF);

    int a2 = t0[a1 & 0xF] & 0xF;
    int b2 = t1[b1 & 0xF] & 0xF;

    int a3 = a2 ^ b2;
    int b3 = a2 ^ ror4(b2, 1) ^ ((8 * a2) & 0xF);

    int a4 = t2[a3 & 0xF] & 0xF;
    int b4 = t3[b3 & 0xF] & 0xF;

    return (byte) ((b4 << 4) | a4);
  }

  private static int ror4(int val, int n) {
    return ((val >>> n) | (val << (4 - n))) & 0xF;
  }

  private static int multiplyWithMds(byte[] y, int mask) {
    int[] result = new int[4];

    for (int i = 0; i < 4; i++) {
      int acc = 0;
      for (int j = 0; j < 4; j++) {
        acc ^= multiplyInGF256(
                TwoFishConfig.MDS_MATRIX[i][j],
                y[j] & 0xFF,
                mask
        );
      }
      result[i] = acc;
    }
    return (result[0] & 0xFF) | ((result[1] & 0xFF) << 8) |
           ((result[2] & 0xFF) << 16) | ((result[3] & 0xFF) << 24);
  }

  public static int multiplyInGF256(int a, int b, int mask) {
    int result = 0;
    for (int i = 0; i < 8; i++) {
      if ((b & 1) != 0) {
        result ^= a;
      }
      boolean carry = (a & 0x80) != 0;
      a <<= 1;
      if (carry) {
        a ^= mask;
      }
      b >>= 1;
    }
    return result & 0xFF;
  }

  public static int ROL(int x, int n) {
    return (x << n) | (x >>> (32 - n));
  }

  public static int ROR(int x, int n) {
    return (x >>> n) | (x << (32 - n));
  }

  public static int[] convertTo32BitWords(byte[] bytes) {
    int[] parts = new int[bytes.length / 4];
    for (int i = 0; i < parts.length; i++) {
      int result = 0;
      for (int j = 0; j < parts.length; j++) {
        result |= ((bytes[4 * i + j] & 0xFF) << (8 * j));
      }
      parts[i] = result;
    }
    return parts;
  }

}
