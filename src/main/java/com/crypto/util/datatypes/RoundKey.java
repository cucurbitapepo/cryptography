package com.crypto.util.datatypes;

import lombok.Getter;

public class RoundKey {

  @Getter
  private byte[] data;

  public RoundKey(byte[] data) {
    this.data = data;
  }

}
