package com.crypto.deal;

import com.crypto.cipher.transformation.CipherTransformation;
import com.crypto.des.DesCipher;
import com.crypto.util.datatypes.Block;
import com.crypto.util.datatypes.Key;
import com.crypto.util.datatypes.RoundKey;

public class DesToCipherTransformationAdapter implements CipherTransformation {

  private final DesCipher desCipher = new DesCipher();

  @Override
  public Block transform(Block block, RoundKey roundKey) {
    desCipher.setRoundKeys(new Key(roundKey.getData()));
    return desCipher.encryptBlock(block);
  }
}
