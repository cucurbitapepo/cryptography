package com.crypto.cipher.serpent;

import com.crypto.cipher.context.SymmetricCipherContext;
import com.crypto.serpent.SerpentCipher;
import com.crypto.util.datatypes.Key;
import com.crypto.util.datatypes.Message;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class SerpentTest {

  @Test
  void testEncryptMessage() { //fails

    byte[] keyBytes = new byte[]{
            (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
    };
    byte[] messageBytes = new byte[]{
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
    };
    Key key = new Key(keyBytes);

    SymmetricCipherContext context = new SymmetricCipherContext(
            key,
            SymmetricCipherContext.EncryptionMode.CTR,
            SymmetricCipherContext.PaddingMode.ANSI_X923,
            new SerpentCipher(),
            new byte[16]
    );

    Message message = new Message(messageBytes, 16);

    Message encryptedMessage = context.encrypt(message);

    //A223AA1288463C0E2BE38EBD825616C0 according to test vectors from https://biham.cs.technion.ac.il/Reports/Serpent/Serpent-256-128.verified.test-vectors
    byte[] expectedResult = new byte[]{(byte) 0xA2, (byte) 0x23, (byte) 0xAA, (byte) 0x12, (byte) 0x88, (byte) 0x46, (byte) 0x3C, (byte) 0x0E,
            (byte) 0x2B, (byte) 0xE3, (byte) 0x8E, (byte) 0xBD, (byte) 0x82, (byte) 0x56, (byte) 0x16, (byte) 0xC0};
    assertArrayEquals(expectedResult, encryptedMessage.getData());
  }

  @Test
  void testEncryptDecryptMessage() { //fails

    byte[] keyBytes = new byte[]{
            (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
    };
    byte[] messageBytes = new byte[]{
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
    };
    Key key = new Key(keyBytes);

    SymmetricCipherContext context = new SymmetricCipherContext(
            key,
            SymmetricCipherContext.EncryptionMode.ECB,
            SymmetricCipherContext.PaddingMode.ZEROS,
            new SerpentCipher(),
            new byte[8]
    );

    Message message = new Message(messageBytes, 16);
    Message encryptedMessage = context.encrypt(message);
    Message decryptedMessage = context.decrypt(encryptedMessage);

    assertArrayEquals(message.getData(), decryptedMessage.getData());
  }

  @ParameterizedTest
  @MethodSource("provideEncryptionAndPaddingModes")
  void testFileEncryptionAndDecryption( //fails on all modes but CFB, OFB, CTR
          SymmetricCipherContext.EncryptionMode encryptionMode,
          SymmetricCipherContext.PaddingMode paddingMode) {
    byte[] keyBytes = new byte[]{
            (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
    };

    Key key = new Key(keyBytes);

    String sourceFilePath = "src/test/resources/desTestBTree.h";
    String encryptedFilePath = "src/test/resources/desTestEncrypted.h";
    String decryptedFilePath = "src/test/resources/desTestDecrypted.h";

    SymmetricCipherContext serpentCipherContext = new SymmetricCipherContext(
            key,
            encryptionMode,
            paddingMode,
            new SerpentCipher(),
            new byte[16]
    );

    serpentCipherContext.setBlockSize(16);

    assertDoesNotThrow(() -> {
      CompletableFuture<Void> encryptionTask = serpentCipherContext.encrypt(sourceFilePath, encryptedFilePath);
      encryptionTask.join();

      CompletableFuture<Void> decryptionTask = serpentCipherContext.decrypt(encryptedFilePath, decryptedFilePath);
      decryptionTask.join();
    }, "something went wrong");

    assertDoesNotThrow(() -> {
      byte[] originalContent = Files.readAllBytes(Path.of(sourceFilePath));
      byte[] decryptedContent = Files.readAllBytes(Path.of(decryptedFilePath));

      assertArrayEquals(originalContent, decryptedContent,
              "Содержимое исходного и расшифрованного файлов не совпадает");
    }, "Ошибка при чтении файлов для сравнения");
  }

  private static Stream<Arguments> provideEncryptionAndPaddingModes() {
    return Stream.of(
                    SymmetricCipherContext.EncryptionMode.values())
            .filter(mode -> !mode.equals(SymmetricCipherContext.EncryptionMode.RANDOM_DELTA))
            .flatMap(encryptionMode ->
                    Stream.of(SymmetricCipherContext.PaddingMode.values())
                            .map(paddingMode -> Arguments.of(encryptionMode, paddingMode))
            );
  }
}