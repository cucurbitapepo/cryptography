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
  void testEncryptMessage() {

    byte[] keyBytes = new byte[]{
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
    };
    byte[] messageBytes = new byte[]{
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01
    };
    Key key = new Key(keyBytes);

    SymmetricCipherContext context = new SymmetricCipherContext(
            key,
            SymmetricCipherContext.EncryptionMode.ECB,
            SymmetricCipherContext.PaddingMode.ANSI_X923,
            new SerpentCipher(),
            new byte[16]
    );

    //AD86DE83231C3203A86AE33B721EAA9F according to BC implementation
    byte[] expectedResult = new byte[]{(byte) 0xAD, (byte) 0x86, (byte) 0xDE, (byte) 0x83, (byte) 0x23, (byte) 0x1C, (byte) 0x32, (byte) 0x03,
            (byte) 0xA8, (byte) 0x6A, (byte) 0xE3, (byte) 0x3B, (byte) 0x72, (byte) 0x1E, (byte) 0xAA, (byte) 0x9F};

    Message message = new Message(messageBytes, 16);

    Message encryptedMessage = context.encrypt(message);


    assertArrayEquals(expectedResult, encryptedMessage.getData());
  }

  @ParameterizedTest
  @MethodSource("provideEncryptionAndPaddingModesWithoutZeros")
  void testEncryptDecryptMessage(
          SymmetricCipherContext.EncryptionMode encryptionMode,
          SymmetricCipherContext.PaddingMode paddingMode) {
    // here ZEROS mode is excluded due to plaintext being only zeroes itself

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
            encryptionMode,
            paddingMode,
            new SerpentCipher(),
            new byte[16]
    );

    Message message = new Message(messageBytes, 16);
    Message encryptedMessage = context.encrypt(message);
    Message decryptedMessage = context.decrypt(encryptedMessage);

    assertArrayEquals(message.getData(), decryptedMessage.getData());
  }

  private static Stream<Arguments> provideEncryptionAndPaddingModesWithoutZeros() {
    return Stream.of(
                    SymmetricCipherContext.EncryptionMode.values())
            .filter(mode -> !mode.equals(SymmetricCipherContext.EncryptionMode.RANDOM_DELTA))
            .flatMap(encryptionMode ->
                    Stream.of(SymmetricCipherContext.PaddingMode.values())
                            .filter(paddingMode -> !paddingMode.equals(SymmetricCipherContext.PaddingMode.ZEROS))
                            .map(paddingMode -> Arguments.of(encryptionMode, paddingMode))
            );
  }

  @ParameterizedTest
  @MethodSource("provideEncryptionAndPaddingModes")
  void testFileEncryptionAndDecryption(
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
            .flatMap(encryptionMode ->
                    Stream.of(SymmetricCipherContext.PaddingMode.values())
                            .map(paddingMode -> Arguments.of(encryptionMode, paddingMode))
            );
  }
}