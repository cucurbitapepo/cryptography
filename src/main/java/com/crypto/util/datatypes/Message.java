package com.crypto.util.datatypes;

import lombok.Getter;
import lombok.Setter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Getter
@Setter
public class Message {

  private Block[] blocks;
  private int blockSize;

  public Message(byte[] data, int blockSize) {
    this.blockSize = blockSize;
    this.blocks = splitIntoBlocks(data, blockSize);
  }

  public Message(Message message) {
    this.blockSize = message.blockSize;
    this.blocks = message.blocks.clone();
  }

  public Message(String text, int blockSize) {
    this(text.getBytes(), blockSize);
  }

  @Override
  public String toString() {
    byte[] data = getData();
    return new String(data, StandardCharsets.UTF_8);
  }

  public Message(Block[] blocks, int blockSize) {
    this.blocks = blocks;
    this.blockSize = blockSize;
  }

  public byte[] getData() {
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    for (Block block : blocks) {
      try {
        outputStream.write(block.getData());
      } catch (IOException e) {
        throw new RuntimeException("Ошибка при объединении блоков", e);
      }
    }
    return outputStream.toByteArray();
  }

  public Block[] splitIntoBlocks(byte[] data, int blockSize) {
    List<Block> splitBlocks = new ArrayList<>();
    for (int i = 0; i < data.length; i += blockSize) {
      int length = Math.min(blockSize, data.length - i);
      splitBlocks.add(new Block(Arrays.copyOfRange(data, i, i + length)));
    }
    return splitBlocks.toArray(new Block[0]);
  }
}
