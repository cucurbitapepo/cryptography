package com.crypto.cipher.context;

import com.crypto.cipher.SymmetricCipher;
import com.crypto.util.BitUtils;
import com.crypto.util.datatypes.Block;
import com.crypto.util.datatypes.Key;
import com.crypto.util.datatypes.Message;
import lombok.Setter;

import java.io.*;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;

public class SymmetricCipherContext {

  private final EncryptionMode encryptionMode;
  private final byte[] initializationVector;
  private final PaddingMode paddingMode;
  private final Key key;

  private final SymmetricCipher symmetricCipher;

  @Setter
  private int blockSize;

  public enum EncryptionMode {
    ECB, CBC, PCBC, CFB, OFB, CTR, RANDOM_DELTA
  }

  public enum PaddingMode {
    ZEROS, ANSI_X923, PKCS7, ISO_10126
  }

  /**
   * Устанавливает значения encryptionMode, paddingMode.
   *
   * @param encryptionKey        Ключ шифрования.
   * @param encryptionMode       Режим шифрования.
   * @param paddingMode          Режим набивки.
   * @param initializationVector Вектор инициализации для режима шифрования.
   * @param additionalParameters Дополнительные параметры.
   */
  public SymmetricCipherContext(
          Key encryptionKey,
          EncryptionMode encryptionMode,
          PaddingMode paddingMode,
          SymmetricCipher symmetricCipherImplementation,
          byte[] initializationVector,
          Object... additionalParameters) {
    if (encryptionKey == null ||
        encryptionMode == null ||
        paddingMode == null ||
        symmetricCipherImplementation == null) {
      throw new IllegalArgumentException("Invalid constructor parameters");
    }
    this.encryptionMode = encryptionMode;
    this.paddingMode = paddingMode;
    this.symmetricCipher = symmetricCipherImplementation;
    this.initializationVector = initializationVector;
    this.key = encryptionKey;
    symmetricCipher.setRoundKeys(key);
  }

  public Message encrypt(Message toEncrypt) {
    blockSize = toEncrypt.getBlockSize();

    Message message = new Message(toEncrypt);

    Block[] blocks = message.getBlocks();
    blocks[blocks.length - 1] = applyPadding(blocks[blocks.length - 1].getData(), message.getBlockSize());
    blocks = processWithMode(encryptionMode, blocks, Operation.ENCRYPT);
    return new Message(blocks, message.getBlockSize());
  }

  public Message decrypt(Message toDecrypt) {
    blockSize = toDecrypt.getBlockSize();
    Message message = new Message(toDecrypt);

    Block[] blocks = message.getBlocks();
    if (blocks[blocks.length - 1].getData().length != blockSize) {
      throw new IllegalArgumentException("Message last block size is wrong.");
    }

    blocks = processWithMode(encryptionMode, blocks, Operation.DECRYPT);
    Message decryptedMessage = new Message(blocks, 8);
    removePadding(decryptedMessage);

    return decryptedMessage;
  }

  private Block applyPadding(byte[] block, int targetBlockSize) {
    int paddingLength = (targetBlockSize - (block.length % targetBlockSize)) % targetBlockSize;
    byte[] paddedData = Arrays.copyOf(block, block.length + paddingLength);
    if (paddingLength != 0) {
      switch (paddingMode) {
        case ZEROS: {
          Arrays.fill(paddedData, block.length, paddedData.length, (byte) 0x00);
          break;
        }
        case ANSI_X923: {
          Arrays.fill(paddedData, block.length, paddedData.length - 1, (byte) 0x00);
          paddedData[paddedData.length - 1] = (byte) paddingLength;
          break;
        }
        case PKCS7: {
          Arrays.fill(paddedData, block.length, paddedData.length, (byte) paddingLength);
          break;
        }
        case ISO_10126: {
          Random random = new Random();
          byte[] randomBytes = new byte[paddingLength - 1];
          random.nextBytes(randomBytes);

          System.arraycopy(randomBytes, 0, paddedData, block.length, randomBytes.length);
          paddedData[paddedData.length - 1] = (byte) paddingLength;
          break;
        }
      }
    }

    return new Block(paddedData);
  }

  private void removePadding(Message message) {
    Block[] blocks = message.getBlocks();
    if (blocks.length == 0) {
      throw new IllegalArgumentException("Message contains no blocks");
    }

    Block lastBlock = blocks[blocks.length - 1];
    byte[] blockData = lastBlock.getData();

    int paddingLength = 0;
    switch (paddingMode) {
      case ZEROS:
        while (paddingLength < blockData.length && blockData[blockData.length - 1 - paddingLength] == 0x00) {
          paddingLength++;
        }
        break;

      case ANSI_X923, PKCS7, ISO_10126:
        paddingLength = blockData[blockData.length - 1] & 0xFF;
        if (paddingLength > blockSize) {
          //assuming there was no padding at all
          return;
        }
        break;
      default:
        throw new IllegalStateException("Unsupported padding mode: " + paddingMode);
    }

    byte[] unpaddedData = Arrays.copyOf(blockData, blockData.length - paddingLength);

    blocks[blocks.length - 1] = new Block(unpaddedData);
  }

  private enum Operation {
    ENCRYPT,
    DECRYPT
  }

  private Block[] processWithMode(EncryptionMode mode, Block[] blocks, Operation operation) {
    return switch (mode) {
      case ECB -> processWithECB(blocks, operation);
      case CBC -> processWithCBC(blocks, operation);
      case PCBC -> processWithPCBC(blocks, operation);
      case CFB -> processWithCFB(blocks, operation);
      case OFB -> processWithOFB(blocks, operation);
      case CTR -> processWithCTR(blocks, operation);
      case RANDOM_DELTA -> processWithRandomDelta(blocks, operation);
      default -> throw new IllegalArgumentException("Unsupported encryption mode: " + mode);
    };
  }

  private Block[] processWithECB(Block[] blocks, Operation operation) {
    return Arrays.stream(blocks)
            .parallel()
            .map(block -> {
              byte[] processedData;
              if (operation.equals(Operation.ENCRYPT)) {
                processedData = symmetricCipher.encryptBlock(block).getData();
              } else {
                processedData = symmetricCipher.decryptBlock(block).getData();
              }
              return new Block(processedData);
            })
            .toArray(Block[]::new);
  }

  private Block[] processWithCBC(Block[] blocks, Operation operation) {

    if (initializationVector != null && initializationVector.length != blockSize) {
      throw new IllegalStateException("Initialization vector length does not match initialization vector length");
    }

    final byte[][] previousBlock = {initializationVector};

    return Arrays.stream(blocks)
            .map(block -> {
              byte[] processedData;

              if (operation.equals(Operation.ENCRYPT)) {
                byte[] xoredBlock = BitUtils.xor(block.getData(), previousBlock[0]);
                Block encryptedBlock = symmetricCipher.encryptBlock(new Block(xoredBlock));
                processedData = encryptedBlock.getData();
                previousBlock[0] = processedData;
              } else {
                Block decryptedBlock = symmetricCipher.decryptBlock(block);
                processedData = BitUtils.xor(decryptedBlock.getData(), previousBlock[0]);
                previousBlock[0] = block.getData();
              }

              return new Block(processedData);
            })
            .toArray(Block[]::new);
  }

  private Block[] processWithOFB(Block[] blocks, Operation operation) {
    final byte[][] previousBlock = {initializationVector};

    return Arrays.stream(blocks)
            .map(block -> {
              byte[] currentBlockData = block.getData();
              byte[] keyStream = symmetricCipher.encryptBlock(new Block(previousBlock[0])).getData();
              byte[] processedData = BitUtils.xor(currentBlockData, keyStream);
              previousBlock[0] = keyStream;
              return new Block(processedData);
            })
            .toArray(Block[]::new);
  }

  private Block[] processWithCTR(Block[] blocks, Operation operation) {
    AtomicInteger counter = new AtomicInteger(0);

    return Arrays.stream(blocks)
            .map(block -> {
              byte[] currentBlockData = block.getData();
              byte[] counterBlock = generateCounterBlock(counter.getAndIncrement());
              byte[] keyStream = symmetricCipher.encryptBlock(new Block(counterBlock)).getData();
              byte[] processedData = BitUtils.xor(currentBlockData, keyStream);
              return new Block(processedData);
            })
            .toArray(Block[]::new);
  }

  private byte[] generateCounterBlock(int counterValue) {
    byte[] counterBlock = new byte[this.blockSize];
    ByteBuffer.wrap(counterBlock).putInt(counterValue);
    return counterBlock;
  }

  private Block[] processWithPCBC(Block[] blocks, Operation operation) {
    final byte[][] previousCipherBlock = {initializationVector};
    final byte[][] previousPlainBlock = {new byte[blocks[0].getData().length]};

    return Arrays.stream(blocks)
            .map(block -> {
              byte[] processedData;

              if (operation.equals(Operation.ENCRYPT)) {
                byte[] xoredBlock = BitUtils.xor(BitUtils.xor(block.getData(), previousPlainBlock[0]), previousCipherBlock[0]);
                Block encryptedBlock = symmetricCipher.encryptBlock(new Block(xoredBlock));
                processedData = encryptedBlock.getData();
                previousCipherBlock[0] = processedData;
                previousPlainBlock[0] = block.getData();
              } else {
                Block decryptedBlock = symmetricCipher.decryptBlock(block);
                processedData = BitUtils.xor(BitUtils.xor(decryptedBlock.getData(), previousCipherBlock[0]), previousPlainBlock[0]);
                previousCipherBlock[0] = block.getData();
                previousPlainBlock[0] = processedData;
              }

              return new Block(processedData);
            })
            .toArray(Block[]::new);
  }

  private Block[] processWithCFB(Block[] blocks, Operation operation) {

    final byte[][] previousBlock = {initializationVector};

    return Arrays.stream(blocks).
            map(block -> {
              byte[] currentBlockData = block.getData();
              byte[] processedData;

              if (operation.equals(Operation.ENCRYPT)) {
                byte[] keyStream = symmetricCipher.encryptBlock(new Block(previousBlock[0])).getData();
                processedData = BitUtils.xor(currentBlockData, keyStream);
                previousBlock[0] = processedData;
              } else {
                byte[] keyStream = symmetricCipher.encryptBlock(new Block(previousBlock[0])).getData();
                processedData = BitUtils.xor(currentBlockData, keyStream);
                previousBlock[0] = block.getData();
              }

              return new Block(processedData);
            }).
            toArray(Block[]::new);
  }

  private Block[] processWithRandomDelta(Block[] blocks, Operation operation) {
    throw new UnsupportedOperationException("actually have no idea what this supposed to do :(");
  }

  public CompletableFuture<Void> encrypt(String sourceFilePath, String encryptedFilePath) {
    if (this.blockSize <= 0) {
      throw new IllegalStateException("blockSize must be greater than 0");
    }
    return CompletableFuture.runAsync(() -> {
      try (BufferedInputStream inputStream = new BufferedInputStream(new FileInputStream(sourceFilePath));
           BufferedOutputStream outputStream = new BufferedOutputStream(new FileOutputStream(encryptedFilePath))) {

        byte[] buffer = new byte[1024 * blockSize];
        int bytesRead;
        boolean isLastBlock = false;

        while ((bytesRead = inputStream.read(buffer)) != -1) {
          if (bytesRead < buffer.length) {
            buffer = Arrays.copyOf(buffer, bytesRead);
            buffer = applyPadding(buffer, blockSize).getData();
            isLastBlock = true;
          }

          List<Block> blocks = splitIntoBlocks(buffer, bytesRead, blockSize);
          Block[] encryptedBlocks = processWithMode(encryptionMode, blocks.toArray(new Block[0]), Operation.ENCRYPT);
          for (Block block : encryptedBlocks) {
            outputStream.write(block.getData());
          }
          if (isLastBlock) {
            break;
          }
        }
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
    });
  }

  public CompletableFuture<Void> decrypt(String encryptedFilePath, String decryptedFilePath) {
    if (this.blockSize <= 0) {
      throw new IllegalStateException("blockSize must be greater than 0");
    }
    return CompletableFuture.runAsync(() -> {
      try (BufferedInputStream inputStream = new BufferedInputStream(new FileInputStream(encryptedFilePath));
           BufferedOutputStream outputStream = new BufferedOutputStream(new FileOutputStream(decryptedFilePath))) {
        byte[] buffer = new byte[1024 * blockSize];
        int bytesRead;

        while ((bytesRead = inputStream.read(buffer)) != -1) {
          List<Block> blocks = splitIntoBlocks(buffer, bytesRead, blockSize);
          Block[] decryptedBlocks = processWithMode(encryptionMode, blocks.toArray(new Block[0]), Operation.DECRYPT);

          if (bytesRead < buffer.length) {
            Message decryptedMessage = new Message(decryptedBlocks, blockSize);
            removePadding(decryptedMessage);
          }

          for (Block block : decryptedBlocks) {
            outputStream.write(block.getData());
          }
        }
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
    });
  }

  private List<Block> splitIntoBlocks(byte[] data, int length, int blockSize) {
    List<Block> blocks = new ArrayList<>();
    for (int i = 0; i < length; i += blockSize) {
      blocks.add(new Block(Arrays.copyOfRange(data, i, i + blockSize)));
    }
    return blocks;
  }

}
