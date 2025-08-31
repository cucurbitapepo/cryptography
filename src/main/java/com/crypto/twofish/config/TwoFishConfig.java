package com.crypto.twofish.config;

public class TwoFishConfig {

  public static final int[] VALID_KEY_SIZES = {16, 24, 32};

  // GF(2^8) polynoms
  public static final int GF_256_FDBK = 0x169; // x^8 + x^6 + x^5 + x^3 + 1
  public static final int RS_GF_FDBK = 0x14D; // x^8 + x^5 + x^3 + x^2 + 1

  // constants for round keys generation
  public static final int RHO = 0x01010101;
  public static final int NUM_ROUNDS = 16;
  public static final int NUM_WHITENING_KEYS = 8;
  public static final int TOTAL_ROUND_KEYS = NUM_WHITENING_KEYS + 2 * NUM_ROUNDS; // 40

  // maximum distance separable matrix
  public static final byte[][] MDS_MATRIX = {
          {(byte) 0x01, (byte) 0xEF, (byte) 0x5B, (byte) 0x5B},
          {(byte) 0x5B, (byte) 0xEF, (byte) 0xEF, (byte) 0x01},
          {(byte) 0xEF, (byte) 0x5B, (byte) 0x01, (byte) 0xEF},
          {(byte) 0xEF, (byte) 0x01, (byte) 0xEF, (byte) 0x5B}
  };

  public static final byte[][] RS = {
          {(byte) 0x01, (byte) 0xA4, (byte) 0x55, (byte) 0x87, (byte) 0x5A, (byte) 0x58, (byte) 0xDB, (byte) 0x9E},
          {(byte) 0xA4, (byte) 0x56, (byte) 0x82, (byte) 0xF3, (byte) 0x1E, (byte) 0xC6, (byte) 0x68, (byte) 0xE5},
          {(byte) 0x02, (byte) 0xA1, (byte) 0xFC, (byte) 0xC1, (byte) 0x47, (byte) 0xAE, (byte) 0x3D, (byte) 0x19},
          {(byte) 0xA4, (byte) 0x55, (byte) 0x87, (byte) 0x5A, (byte) 0x58, (byte) 0xDB, (byte) 0x9E, (byte) 0x03}
  };

  public static final byte[] q0_t0 = {
          (byte) 0x8, (byte) 0x1, (byte) 0x7, (byte) 0xD,
          (byte) 0x6, (byte) 0xF, (byte) 0x3, (byte) 0x2,
          (byte) 0x0, (byte) 0xB, (byte) 0x5, (byte) 0x9,
          (byte) 0xE, (byte) 0xC, (byte) 0xA, (byte) 0x4
  };
  public static final byte[] q0_t1 = {
          (byte) 0xE, (byte) 0xC, (byte) 0xB, (byte) 0x8,
          (byte) 0x1, (byte) 0x2, (byte) 0x3, (byte) 0x5,
          (byte) 0xF, (byte) 0x4, (byte) 0xA, (byte) 0x6,
          (byte) 0x7, (byte) 0x0, (byte) 0x9, (byte) 0xD
  };

  public static final byte[] q0_t2 = {
          (byte) 0xB, (byte) 0xA, (byte) 0x5, (byte) 0xE,
          (byte) 0x6, (byte) 0xD, (byte) 0x9, (byte) 0x0,
          (byte) 0xC, (byte) 0x8, (byte) 0xF, (byte) 0x3,
          (byte) 0x2, (byte) 0x4, (byte) 0x7, (byte) 0x1
  };
  public static final byte[] q0_t3 = {
          (byte) 0xD, (byte) 0x7, (byte) 0xF, (byte) 0x4,
          (byte) 0x1, (byte) 0x2, (byte) 0x6, (byte) 0xE,
          (byte) 0x9, (byte) 0xB, (byte) 0x3, (byte) 0x0,
          (byte) 0x8, (byte) 0x5, (byte) 0xC, (byte) 0xA
  };

  public static final byte[] q1_t0 = {
          (byte) 0x2, (byte) 0x8, (byte) 0xB, (byte) 0xD,
          (byte) 0xF, (byte) 0x7, (byte) 0x6, (byte) 0xE,
          (byte) 0x3, (byte) 0x1, (byte) 0x9, (byte) 0x4,
          (byte) 0x0, (byte) 0xA, (byte) 0xC, (byte) 0x5
  };
  public static final byte[] q1_t1 = {
          (byte) 0x1, (byte) 0xE, (byte) 0x2, (byte) 0xB,
          (byte) 0x4, (byte) 0xC, (byte) 0x3, (byte) 0x7,
          (byte) 0x6, (byte) 0xD, (byte) 0xA, (byte) 0x5,
          (byte) 0xF, (byte) 0x9, (byte) 0x0, (byte) 0x8
  };
  public static final byte[] q1_t2 = {
          (byte) 0x4, (byte) 0xC, (byte) 0x7, (byte) 0x5,
          (byte) 0x1, (byte) 0x6, (byte) 0x9, (byte) 0xA,
          (byte) 0x0, (byte) 0xE, (byte) 0xD, (byte) 0x8,
          (byte) 0x2, (byte) 0xB, (byte) 0x3, (byte) 0xF
  };
  public static final byte[] q1_t3 = {
          (byte) 0xB, (byte) 0x9, (byte) 0x5, (byte) 0x1,
          (byte) 0xC, (byte) 0x3, (byte) 0xD, (byte) 0xE,
          (byte) 0x6, (byte) 0x4, (byte) 0x7, (byte) 0xF,
          (byte) 0x2, (byte) 0x0, (byte) 0x8, (byte) 0xA
  };
}
