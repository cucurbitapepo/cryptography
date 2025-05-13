package com.crypto.lab1.des;

import com.crypto.cipher.context.SymmetricCipherContext;
import com.crypto.des.DesCipher;
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

class DesTest {

  @Test
  void testDecryptMessage() {
    byte[] keyBytes = new byte[]{
            (byte) 0x11, (byte) 0x11, (byte) 0x11, (byte) 0x11,
            (byte) 0x11, (byte) 0x11, (byte) 0x11, (byte) 0x11
    };
    byte[] messageBytes = new byte[]{
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
    };

    Key key = new Key(keyBytes);

    SymmetricCipherContext context = new SymmetricCipherContext(
            key,
            SymmetricCipherContext.EncryptionMode.CTR,
            SymmetricCipherContext.PaddingMode.ANSI_X923,
            new DesCipher(),
            new byte[8]
    );

    Message message = new Message(messageBytes, 8);

    Message encryptedMessage = context.encrypt(message);
    Message decryptedMessage = context.decrypt(encryptedMessage);

    assertArrayEquals(messageBytes, decryptedMessage.getBlocks()[0].getData());
  }

  @Test
  void testEncryptMessage() {

    byte[] keyBytes = new byte[]{
            (byte) 0x11, (byte) 0x11, (byte) 0x11, (byte) 0x11,
            (byte) 0x11, (byte) 0x11, (byte) 0x11, (byte) 0x11
    };
    byte[] messageBytes = new byte[]{
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
    };

    Key key = new Key(keyBytes);

    SymmetricCipherContext context = new SymmetricCipherContext(
            key,
            SymmetricCipherContext.EncryptionMode.ECB,
            SymmetricCipherContext.PaddingMode.PKCS7,
            new DesCipher(),
            null
    );

    Message message = new Message(messageBytes, 8);

    Message encryptedMessage = context.encrypt(message);

    byte[] expectedEncryptedData = new byte[]{
            (byte) 0x82, (byte) 0xE1, (byte) 0x36, (byte) 0x65,
            (byte) 0xB4, (byte) 0x62, (byte) 0x4D, (byte) 0xF5
    };

    assertArrayEquals(expectedEncryptedData, encryptedMessage.getData(),
            "Encrypted block does not match expected result");
  }

  @Test
  void testEncryptAndDecryptMessageOnce() {
    String messageString = "Hello, World!";
    String keyString = "8bytekey";
    Message message = new Message(messageString, 8);
    Key key = new Key(keyString);

    SymmetricCipherContext desCipherContext = new SymmetricCipherContext(
            key,
            SymmetricCipherContext.EncryptionMode.ECB,
            SymmetricCipherContext.PaddingMode.ZEROS,
            new DesCipher(),
            new byte[8]
    );

    Message encryptedMessage = desCipherContext.encrypt(message);
    Message decryptedMessage = desCipherContext.decrypt(encryptedMessage);

    assertEquals(message.toString(), decryptedMessage.toString());
  }

  @Test
  void testFileEncryptionAndDecryptionSingle() {
    String KeyString = "8bytekey";
    Key key = new Key(KeyString);

    String sourceFilePath = "src\\test\\resources\\desTestBTree.h";
    String encryptedFilePath = "src\\test\\resources\\desTestEncrypted.h";
    String decryptedFilePath = "src\\test\\resources\\desTestDecrypted.h";
    SymmetricCipherContext desCipherContext = new SymmetricCipherContext(
            key,
            SymmetricCipherContext.EncryptionMode.OFB,
            SymmetricCipherContext.PaddingMode.ANSI_X923,
            new DesCipher(),
            new byte[]{1, 1, 1, 1, 1, 1, 1, 1}
    );

    desCipherContext.setBlockSize(8);

    assertDoesNotThrow(() -> {
      CompletableFuture<Void> encryptionTask = desCipherContext.encrypt(sourceFilePath, encryptedFilePath);
      encryptionTask.join();

      CompletableFuture<Void> decryptionTask = desCipherContext.decrypt(encryptedFilePath, decryptedFilePath);
      decryptionTask.join();
    }, "something went wrong");

    assertDoesNotThrow(() -> {
      byte[] originalContent = Files.readAllBytes(Path.of(sourceFilePath));
      byte[] decryptedContent = Files.readAllBytes(Path.of(decryptedFilePath));

      assertArrayEquals(originalContent, decryptedContent, "Содержимое исходного и расшифрованного файлов не совпадает");
    }, "Ошибка при чтении файлов для сравнения");

  }


  @ParameterizedTest
  @MethodSource("provideEncryptionAndPaddingModes")
  void testFileEncryptionAndDecryption(
          SymmetricCipherContext.EncryptionMode encryptionMode,
          SymmetricCipherContext.PaddingMode paddingMode) {
    String keyString = "8bytekey";
    Key key = new Key(keyString);

    String sourceFilePath = "src/test/resources/desTestBTree.h";
    String encryptedFilePath = "src/test/resources/desTestEncrypted.h";
    String decryptedFilePath = "src/test/resources/desTestDecrypted.h";

    SymmetricCipherContext desCipherContext = new SymmetricCipherContext(
            key,
            encryptionMode,
            paddingMode,
            new DesCipher(),
            new byte[]{1, 1, 1, 1, 1, 1, 1, 1}
    );

    desCipherContext.setBlockSize(8);

    assertDoesNotThrow(() -> {
      CompletableFuture<Void> encryptionTask = desCipherContext.encrypt(sourceFilePath, encryptedFilePath);
      encryptionTask.join();

      CompletableFuture<Void> decryptionTask = desCipherContext.decrypt(encryptedFilePath, decryptedFilePath);
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
