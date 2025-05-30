package com.crypto.cipher;

import com.crypto.util.datatypes.Block;
import com.crypto.util.datatypes.Key;

public interface SymmetricCipher {

  Block encryptBlock(Block block);

  Block decryptBlock(Block block);

  void setRoundKeys(Key key);

  int getBlockSize();
}
