package com.crypto.lab1.deal;

import com.crypto.cipher.context.SymmetricCipherContext;
import com.crypto.deal.DealCipher;
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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

public class DealTest {
  @Test
  void testDecryptMessage() {
    Key key = new Key("16 byte long key");

    SymmetricCipherContext context = new SymmetricCipherContext(
            key,
            SymmetricCipherContext.EncryptionMode.ECB,
            SymmetricCipherContext.PaddingMode.ANSI_X923,
            new DealCipher(),
            null
    );

    Message message = new Message("This message is for testing. something here. blablabla!@#$%^&*()0987654321", 16);

    Message encryptedMessage = context.encrypt(message);
    Message decryptedMessage = context.decrypt(encryptedMessage);

    assertArrayEquals(message.getData(), decryptedMessage.getData());
  }

  @ParameterizedTest
  @MethodSource("provideEncryptionAndPaddingModes")
  void testFileEncryptionAndDecryption(
          SymmetricCipherContext.EncryptionMode encryptionMode,
          SymmetricCipherContext.PaddingMode paddingMode) {
    String keyString = "16 byte long key";
    Key key = new Key(keyString);

    String sourceFilePath = "src/test/resources/desTestBTree.h";
    String encryptedFilePath = "src/test/resources/desTestEncrypted.h";
    String decryptedFilePath = "src/test/resources/desTestDecrypted.h";

    SymmetricCipherContext dealCipherContext = new SymmetricCipherContext(
            key,
            encryptionMode,
            paddingMode,
            new DealCipher(),
            new byte[16]
    );

    dealCipherContext.setBlockSize(16);

    assertDoesNotThrow(() -> {
      CompletableFuture<Void> encryptionTask = dealCipherContext.encrypt(sourceFilePath, encryptedFilePath);
      encryptionTask.join();

      CompletableFuture<Void> decryptionTask = dealCipherContext.decrypt(encryptedFilePath, decryptedFilePath);
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
