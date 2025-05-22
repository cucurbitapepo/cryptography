package com.crypto.serpent;

import com.crypto.cipher.SubstitutionPermutationNetwork;
import com.crypto.util.BitPermutor;
import com.crypto.util.BitUtils;
import com.crypto.util.datatypes.Block;
import com.crypto.util.datatypes.RoundKey;

import static com.crypto.serpent.config.SerpentConfig.*;

public class SerpentCipher extends SubstitutionPermutationNetwork {

  public SerpentCipher() {
    super(new SerpentKeyExpansion(), 31, 16);
  }

  @Override
  public Block encryptBlock(Block block) {
    byte[] blockData = block.getData();
    if (blockData.length != 16) {
      throw new IllegalArgumentException("Block data length must be 16 bytes");
    }

    byte[] permutedData = BitPermutor.permuteBits(
            blockData,
            IP,
            BitPermutor.BitOrder.MostSignificantToLeastSignificant,
            BitPermutor.StartingBitIndex.ONE
    );

    block = super.encryptBlock(new Block(permutedData));

    blockData = block.getData();

    blockData = performAdditionalRound(blockData, Operation.ENCRYPTION);

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
    if (blockData.length != 16) {
      throw new IllegalArgumentException("Block data length must be 16 bytes");
    }

    byte[] permutedData = BitPermutor.permuteBits(
            blockData,
            IP,
            BitPermutor.BitOrder.MostSignificantToLeastSignificant,
            BitPermutor.StartingBitIndex.ONE
    );

    permutedData = performAdditionalRound(permutedData, Operation.DECRYPTION);

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

  private byte[] performAdditionalRound(byte[] block, Operation operation) {
    return switch (operation) {
      case ENCRYPTION -> perfromAdditionalEncryptionRound(block);
      case DECRYPTION -> perfromAdditionalDecryptionRound(block);
    };
  }

  private byte[] perfromAdditionalEncryptionRound(byte[] block) {
    block = applyKey(block, super.getRoundKeys()[31]);
    block = substituteEncryption(block, 31);
    return applyKey(block, super.getRoundKeys()[32]);
  }

  private byte[] perfromAdditionalDecryptionRound(byte[] block) {
    block = applyKey(block, super.getRoundKeys()[32]);
    block = substituteEncryption(block, 31);
    return applyKey(block, super.getRoundKeys()[31]);
  }

  @Override
  protected byte[] substitute(byte[] data, int roundIndex, Operation operation) {
    return switch (operation) {
      case ENCRYPTION -> substituteEncryption(data, roundIndex);
      case DECRYPTION -> substituteDecryption(data, roundIndex);
    };
  }

  private byte[] substituteEncryption(byte[] data, int roundIndex) {
    byte[] result = new byte[16];
    for(int i = 0; i < 32; i++) {
      byte currentByte = data[i/2];
      int shiftInsideByte = i % 2 * 4;
      result[i/2] |= (byte) (S[roundIndex % 8][((currentByte & 0xff & (0x0F << shiftInsideByte)) >> shiftInsideByte)] << shiftInsideByte);
    }

    return result;
  }

  private byte[] substituteDecryption(byte[] data, int roundIndex) {
    byte[] result = new byte[16];
    for(int i = 0; i < 32; i++) {
      byte currentByte = data[i/2];
      int shiftInsideByte = i % 2 * 4;
      result[i/2] |= (byte) (SInverse[roundIndex % 8][((currentByte & 0xff & (0x0F << shiftInsideByte)) >> shiftInsideByte)] << shiftInsideByte);
    }

    return result;
  }

  /**
   * This method implements Linear Transformation represented in Serpent Algorithm documentation.
   * @param data 128-bit block
   */
  @Override
  protected byte[] permute(byte[] data, Operation operation) {
    return switch (operation) {
      case ENCRYPTION -> linearTransformation(data);
      case DECRYPTION -> inverseLinearTransformation(data);
    };
  }

  private byte[] linearTransformation(byte[] data) {
    byte[][] X = new byte[4][4];
    for(int i = 0; i < 4; i++) {
      System.arraycopy(data, i * 4, X[i], 0, 4);
    }

    X[0] = BitUtils.rotateLeft(X[0], 13, 0, 32);
    X[2] = BitUtils.rotateLeft(X[2], 3, 0, 32);
    X[1] = BitUtils.xor(X[1], BitUtils.xor(X[0], X[2]));
    X[3] = BitUtils.xor(X[3], BitUtils.xor(X[2], BitUtils.rotateLeft(X[0], 3, 0, 32)));
    X[1] = BitUtils.rotateLeft(X[1], 1, 0, 32);
    X[3] = BitUtils.rotateLeft(X[3], 7, 0, 32);
    X[0] = BitUtils.xor(X[0], BitUtils.xor(X[1], X[3]));
    X[2] = BitUtils.xor(X[2], BitUtils.xor(X[3], BitUtils.rotateLeft(X[1], 7, 0, 32)));
    X[0] = BitUtils.rotateLeft(X[0], 5, 0, 32);
    X[2] = BitUtils.rotateLeft(X[2], 22, 0, 32);

    return BitUtils.concatenate(X);
  }

  private byte[] inverseLinearTransformation(byte[] data) {
    byte[][] X = new byte[4][4];
    for(int i = 0; i < 4; i++) {
      System.arraycopy(data, i * 4, X[i], 0, 4);
    }

    X[2] = BitUtils.rotateLeft(X[2], -22, 0, 32);
    X[0] = BitUtils.rotateLeft(X[0], -5, 0, 32);
    X[2] = BitUtils.xor(X[2], BitUtils.xor(X[3], BitUtils.rotateLeft(X[1], 7, 0, 32)));
    X[0] = BitUtils.xor(X[0], BitUtils.xor(X[1], X[3]));
    X[3] = BitUtils.rotateLeft(X[3], -7, 0, 32);
    X[1] = BitUtils.rotateLeft(X[1], -1, 0, 32);
    X[3] = BitUtils.xor(X[3], BitUtils.xor(X[2], BitUtils.rotateLeft(X[0], 3, 0, 32)));
    X[1] = BitUtils.xor(X[1], BitUtils.xor(X[0], X[2]));
    X[2] = BitUtils.rotateLeft(X[2], -3, 0, 32);
    X[0] = BitUtils.rotateLeft(X[0], -13, 0, 32);

    return BitUtils.concatenate(X);
  }

  @Override
  protected byte[] applyKey(byte[] data, RoundKey roundKey) {
    return BitUtils.xor(data, roundKey.getData());
  }

}
