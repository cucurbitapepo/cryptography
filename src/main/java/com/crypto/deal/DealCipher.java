package com.crypto.deal;

import com.crypto.cipher.FeistelNetwork;
import com.crypto.util.datatypes.Block;

public class DealCipher extends FeistelNetwork {

  public DealCipher() {
    super(new DealCipherTransformation(), new DealKeyExpansion());
  }

  @Override
  public Block encryptBlock(Block block) {
    if (block.getData().length != 16) {
      throw new IllegalArgumentException("Block data length must be 16 bytes");
    }

    return super.encryptBlock(block);
  }

  @Override
  public Block decryptBlock(Block block) {
    if (block.getData().length != 16) {
      throw new IllegalArgumentException("Block data length must be 16");
    }

    return super.decryptBlock(block);
  }
}
