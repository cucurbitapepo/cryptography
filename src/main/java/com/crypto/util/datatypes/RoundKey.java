package com.crypto.util.datatypes;

import lombok.Getter;

public class RoundKey {

  @Getter
  private byte[] key;

  public RoundKey(byte[] key) {
    this.key = key;
  }

}
