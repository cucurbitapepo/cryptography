package com.crypto.util.datatypes;

import lombok.Getter;

@Getter
public class Block {

  private final byte[] data;

  public Block(byte[] data) {
    this.data = data;
  }

  public Block(String text) {
    this(text.getBytes());
  }

}
