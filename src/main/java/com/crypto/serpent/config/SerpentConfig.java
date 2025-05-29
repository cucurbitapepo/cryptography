package com.crypto.serpent.config;

public class SerpentConfig {

  public static final int goldenRatio = 0x9E3779B9;

  public static int[] applySBox(int sBoxIndex, int a, int b, int c, int d) {
    int[] X = new int[4];
    switch (sBoxIndex) {
      case 0: applyS0(X, a, b, c, d); break;
      case 1: applyS1(X, a, b, c, d); break;
      case 2: applyS2(X, a, b, c, d); break;
      case 3: applyS3(X, a, b, c, d); break;
      case 4: applyS4(X, a, b, c, d); break;
      case 5: applyS5(X, a, b, c, d); break;
      case 6: applyS6(X, a, b, c, d); break;
      case 7: applyS7(X, a, b, c, d); break;
      default: throw new IllegalArgumentException("Invalid sBoxIndex: " + sBoxIndex);
    }
    return X;
  }

  public static int[] applyInvSBox(int sBoxIndex, int a, int b, int c, int d) {
    int[] X = new int[4];
    switch (sBoxIndex) {
      case 0: applyInvS0(X, a, b, c, d); break;
      case 1: applyInvS1(X, a, b, c, d); break;
      case 2: applyInvS2(X, a, b, c, d); break;
      case 3: applyInvS3(X, a, b, c, d); break;
      case 4: applyInvS4(X, a, b, c, d); break;
      case 5: applyInvS5(X, a, b, c, d); break;
      case 6: applyInvS6(X, a, b, c, d); break;
      case 7: applyInvS7(X, a, b, c, d); break;
      default: throw new IllegalArgumentException("Invalid sBoxIndex: " + sBoxIndex);
    }
    return X;
  }

  public static void applyS0(int[] X, int a, int b, int c, int d) {
    int    t1 = a ^ d;
    int    t3 = c ^ t1;
    int    t4 = b ^ t3;
    X[3] = (a & d) ^ t4;
    int    t7 = a ^ (b & t1);
    X[2] = t4 ^ (c | t7);
    int    t12 = X[3] & (t3 ^ t7);
    X[1] = (~t3) ^ t12;
    X[0] = t12 ^ (~t7);
  }

  public static void applyS1 (int[] X, int a, int b, int c, int d) {
    int    t2 = b ^ (~a);
    int    t5 = c ^ (a | t2);
    X[2] = d ^ t5;
    int    t7 = b ^ (d | t2);
    int    t8 = t2 ^ X[2];
    X[3] = t8 ^ (t5 & t7);
    int    t11 = t5 ^ t7;
    X[1] = X[3] ^ t11;
    X[0] = t5 ^ (t8 & t11);
  }

  public static void applyS2 (int[] X, int a, int b, int c, int d) {
    int    t1 = ~a;
    int    t2 = b ^ d;
    int    t3 = c & t1;
    X[0] = t2 ^ t3;
    int    t5 = c ^ t1;
    int    t6 = c ^ X[0];
    int    t7 = b & t6;
    X[3] = t5 ^ t7;
    X[2] = a ^ ((d | t7) & (X[0] | t5));
    X[1] = (t2 ^ X[3]) ^ (X[2] ^ (d | t1));
  }

  public static void applyS3 (int[] X, int a, int b, int c, int d) {
    int    t1 = a ^ b;
    int    t2 = a & c;
    int    t3 = a | d;
    int    t4 = c ^ d;
    int    t5 = t1 & t3;
    int    t6 = t2 | t5;
    X[2] = t4 ^ t6;
    int    t8 = b ^ t3;
    int    t9 = t6 ^ t8;
    int    t10 = t4 & t9;
    X[0] = t1 ^ t10;
    int    t12 = X[2] & X[0];
    X[1] = t9 ^ t12;
    X[3] = (b | d) ^ (t4 ^ t12);
  }

  public static void applyS4 (int[] X, int a, int b, int c, int d) {
    int    t1 = a ^ d;
    int    t2 = d & t1;
    int    t3 = c ^ t2;
    int    t4 = b | t3;
    X[3] = t1 ^ t4;
    int    t6 = ~b;
    int    t7 = t1 | t6;
    X[0] = t3 ^ t7;
    int    t9 = a & X[0];
    int    t10 = t1 ^ t6;
    int    t11 = t4 & t10;
    X[2] = t9 ^ t11;
    X[1] = (a ^ t3) ^ (t10 & X[2]);
  }

  public static void applyS5 (int[] X, int a, int b, int c, int d) {
    int    t1 = ~a;
    int    t2 = a ^ b;
    int    t3 = a ^ d;
    int    t4 = c ^ t1;
    int    t5 = t2 | t3;
    X[0] = t4 ^ t5;
    int    t7 = d & X[0];
    int    t8 = t2 ^ X[0];
    X[1] = t7 ^ t8;
    int    t10 = t1 | X[0];
    int    t11 = t2 | t7;
    int    t12 = t3 ^ t10;
    X[2] = t11 ^ t12;
    X[3] = (b ^ t7) ^ (X[1] & t12);
  }

  public static void applyS6 (int[] X, int a, int b, int c, int d) {
    int    t1 = ~a;
    int    t2 = a ^ d;
    int    t3 = b ^ t2;
    int    t4 = t1 | t2;
    int    t5 = c ^ t4;
    X[1] = b ^ t5;
    int    t7 = t2 | X[1];
    int    t8 = d ^ t7;
    int    t9 = t5 & t8;
    X[2] = t3 ^ t9;
    int    t11 = t5 ^ t8;
    X[0] = X[2] ^ t11;
    X[3] = (~t5) ^ (t3 & t11);
  }

  public static void applyS7 (int[] X, int a, int b, int c, int d) {
    int    t1 = b ^ c;
    int    t2 = c & t1;
    int    t3 = d ^ t2;
    int    t4 = a ^ t3;
    int    t5 = d | t1;
    int    t6 = t4 & t5;
    X[1] = b ^ t6;
    int    t8 = t3 | X[1];
    int    t9 = a & t4;
    X[3] = t1 ^ t9;
    int    t11 = t4 ^ t8;
    int    t12 = X[3] & t11;
    X[2] = t3 ^ t12;
    X[0] = (~t11) ^ (X[3] & X[2]);
  }

  public static void applyInvS0(int[] X, int a, int b, int c, int d) {
    int    t1 = ~a;
    int    t2 = a ^ b;
    int    t4 = d ^ (t1 | t2);
    int    t5 = c ^ t4;
    X[2] = t2 ^ t5;
    int    t8 = t1 ^ (d & t2);
    X[1] = t4 ^ (X[2] & t8);
    X[3] = (a & t4) ^ (t5 | X[1]);
    X[0] = X[3] ^ (t5 ^ t8);
  }
  public static void applyInvS1(int[] X, int a, int b, int c, int d) {
    int    t1 = b ^ d;
    int    t3 = a ^ (b & t1);
    int    t4 = t1 ^ t3;
    X[3] = c ^ t4;
    int    t7 = b ^ (t1 & t3);
    int    t8 = X[3] | t7;
    X[1] = t3 ^ t8;
    int    t10 = ~X[1];
    int    t11 = X[3] ^ t7;
    X[0] = t10 ^ t11;
    X[2] = t4 ^ (t10 | t11);
  }
  public static void applyInvS2(int[] X, int a, int b, int c, int d) {
    int    t1 = b ^ d;
    int    t2 = ~t1;
    int    t3 = a ^ c;
    int    t4 = c ^ t1;
    int    t5 = b & t4;
    X[0] = t3 ^ t5;
    int    t7 = a | t2;
    int    t8 = d ^ t7;
    int    t9 = t3 | t8;
    X[3] = t1 ^ t9;
    int    t11 = ~t4;
    int    t12 = X[0] | X[3];
    X[1] = t11 ^ t12;
    X[2] = (d & t11) ^ (t3 ^ t12);
  }
  public static void applyInvS3(int[] X, int a, int b, int c, int d) {
    int    t1 = a | b;
    int    t2 = b ^ c;
    int    t3 = b & t2;
    int    t4 = a ^ t3;
    int    t5 = c ^ t4;
    int    t6 = d | t4;
    X[0] = t2 ^ t6;
    int    t8 = t2 | t6;
    int    t9 = d ^ t8;
    X[2] = t5 ^ t9;
    int    t11 = t1 ^ t9;
    int    t12 = X[0] & t11;
    X[3] = t4 ^ t12;
    X[1] = X[3] ^ (X[0] ^ t11);
  }
  public static void applyInvS4(int[] X, int a, int b, int c, int d) {
    int    t1 = c | d;
    int    t2 = a & t1;
    int    t3 = b ^ t2;
    int    t4 = a & t3;
    int    t5 = c ^ t4;
    X[1] = d ^ t5;
    int    t7 = ~a;
    int    t8 = t5 & X[1];
    X[3] = t3 ^ t8;
    int    t10 = X[1] | t7;
    int    t11 = d ^ t10;
    X[0] = X[3] ^ t11;
    X[2] = (t3 & t11) ^ (X[1] ^ t7);
  }
  public static void applyInvS5(int[] X, int a, int b, int c, int d) {
    int    t1 = ~c;
    int    t2 = b & t1;
    int    t3 = d ^ t2;
    int    t4 = a & t3;
    int    t5 = b ^ t1;
    X[3] = t4 ^ t5;
    int    t7 = b | X[3];
    int    t8 = a & t7;
    X[1] = t3 ^ t8;
    int    t10 = a | d;
    int    t11 = t1 ^ t7;
    X[0] = t10 ^ t11;
    X[2] = (b & t10) ^ (t4 | (a ^ c));
  }
  public static void applyInvS6(int[] X, int a, int b, int c, int d) {
    int    t1 = ~a;
    int    t2 = a ^ b;
    int    t3 = c ^ t2;
    int    t4 = c | t1;
    int    t5 = d ^ t4;
    X[1] = t3 ^ t5;
    int    t7 = t3 & t5;
    int    t8 = t2 ^ t7;
    int    t9 = b | t8;
    X[3] = t5 ^ t9;
    int    t11 = b | X[3];
    X[0] = t8 ^ t11;
    X[2] = (d & t1) ^ (t3 ^ t11);
  }
  public static void applyInvS7(int[] X, int a, int b, int c, int d) {
    int t3 = c | (a & b);
    int    t4 = d & (a | b);
    X[3] = t3 ^ t4;
    int    t6 = ~d;
    int    t7 = b ^ t4;
    int    t9 = t7 | (X[3] ^ t6);
    X[1] = a ^ t9;
    X[0] = (c ^ t7) ^ (d | X[1]);
    X[2] = (t3 ^ X[1]) ^ (X[0] ^ (a & X[3]));
  }
}
