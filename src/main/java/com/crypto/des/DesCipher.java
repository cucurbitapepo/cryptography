package com.crypto.des;

import com.crypto.cipher.FeistelNetwork;
import com.crypto.util.BitPermutor;
import com.crypto.util.datatypes.Block;

import static com.crypto.des.config.DesConfiguration.FP;
import static com.crypto.des.config.DesConfiguration.IP;

public class DesCipher extends FeistelNetwork {

  public DesCipher() {
    super(new DesCipherTransformation(), new DesKeyExpansion());
  }

  @Override
  public Block encryptBlock(Block block) {
    byte[] blockData = block.getData();
    if (blockData.length != 8) {
      throw new IllegalArgumentException("Block data length must be 8 bytes");
    }

    byte[] permutedData = BitPermutor.permuteBits(
            blockData,
            IP,
            BitPermutor.BitOrder.MostSignificantToLeastSignificant,
            BitPermutor.StartingBitIndex.ONE
    );

    block = super.encryptBlock(new Block(permutedData));

    blockData = block.getData();

    permutedData = BitPermutor.permuteBits(
            blockData,
            FP,
            BitPermutor.BitOrder.MostSignificantToLeastSignificant,
            BitPermutor.StartingBitIndex.ONE
    );

    return new Block(permutedData);
  }

  @Override
  public Block decryptBlock(Block block) {
    byte[] blockData = block.getData();
    if (blockData.length != 8) {
      throw new IllegalArgumentException("Block data length must be 8");
    }

    byte[] permutedData = BitPermutor.permuteBits(
            blockData,
            IP,
            BitPermutor.BitOrder.MostSignificantToLeastSignificant,
            BitPermutor.StartingBitIndex.ONE
    );

    block = super.decryptBlock(new Block(permutedData));

    blockData = block.getData();

    permutedData = BitPermutor.permuteBits(
            blockData,
            FP,
            BitPermutor.BitOrder.MostSignificantToLeastSignificant,
            BitPermutor.StartingBitIndex.ONE
    );

    return new Block(permutedData);
  }

}
