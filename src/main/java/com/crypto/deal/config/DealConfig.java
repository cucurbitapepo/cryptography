package com.crypto.deal.config;

public class DealConfig {

  public static final byte[] fixedDesKey = new byte[]{
          (byte) 0x12, (byte) 0x34, (byte) 0x56, (byte) 0x78,
          (byte) 0x90, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF
  };

  public static byte[] fixedInitializationVector = new byte[]{
          (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
          (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
  };

}
