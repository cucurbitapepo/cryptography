package com.crypto.cipher.serpent;

import com.crypto.cipher.context.SymmetricCipherContext;
import com.crypto.des.DesCipher;
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
            new byte[8]
    );

    Message message = new Message(messageBytes, 16);

    Message encryptedMessage = context.encrypt(message);

    //A223AA1288463C0E2BE38EBD825616C0
    byte[] expectedResult = new byte[]{(byte) 0xA2, (byte) 0x23, (byte) 0xAA, (byte) 0x12, (byte) 0x88, (byte) 0x46, (byte) 0x3C, (byte) 0x0E,
            (byte) 0x2B, (byte) 0xE3, (byte) 0x8E, (byte) 0xBD, (byte) 0x82, (byte) 0x56, (byte) 0x16, (byte) 0xC0};
    assertArrayEquals(expectedResult, encryptedMessage.getData());
  }
}