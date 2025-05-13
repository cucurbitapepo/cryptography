package com.crypto.util.datatypes;

import lombok.Getter;

@Getter
public class Key {

  private final byte[] data;

  public Key(byte[] data) {
    this.data = data;
  }

  public Key(String keyText) {
    this(keyText.getBytes());
  }

  public int getSize() {
    return data.length;
  }

}
