package com.crypto.cipher.twofish;

import com.crypto.cipher.context.SymmetricCipherContext;
import com.crypto.serpent.SerpentCipher;
import com.crypto.twofish.TwoFishCipher;
import com.crypto.util.datatypes.Key;
import com.crypto.util.datatypes.Message;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

class TwoFishTest {

  private static final HexFormat hex = HexFormat.of();

  @Test
  void testEncryptMessage() {


    byte[] keyBytes = hex.parseHex("00000000000000000000000000000000");

    byte[] messageBytes = hex.parseHex("00000000000000000000000000000000");

    //according to documentation examples
    byte[] expectedResult = hex.parseHex("9F589F5CF6122C32B6BFEC2F2AE8C35A");
    Key key = new Key(keyBytes);

    SymmetricCipherContext context = new SymmetricCipherContext(
            key,
            SymmetricCipherContext.EncryptionMode.ECB,
            SymmetricCipherContext.PaddingMode.ZEROS,
            new TwoFishCipher(),
            new byte[16]
    );


    Message message = new Message(messageBytes, 16);

    Message encryptedMessage = context.encrypt(message);


    assertArrayEquals(expectedResult, encryptedMessage.getData());
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
  @MethodSource("provideEncryptionAndPaddingModesWithoutZeros")
  void testEncryptDecryptMessage(
          SymmetricCipherContext.EncryptionMode encryptionMode,
          SymmetricCipherContext.PaddingMode paddingMode) {

    byte[] keyBytes = hex.parseHex("00000000000000000000000000000000");

    Key key = new Key(keyBytes);

    SymmetricCipherContext context = new SymmetricCipherContext(
            key,
            encryptionMode,
            paddingMode,
            new TwoFishCipher(),
            new byte[16]
    );

    Message message = new Message("I can't believe this works", 16);
    Message encryptedMessage = context.encrypt(message);
    Message decryptedMessage = context.decrypt(encryptedMessage);

    assertArrayEquals(message.getData(), decryptedMessage.getData());
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
            new TwoFishCipher(),
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
