package com.crypto.deal;

import com.crypto.cipher.transformation.CipherTransformation;
import com.crypto.util.datatypes.Block;
import com.crypto.util.datatypes.RoundKey;

public class DealCipherTransformation implements CipherTransformation {
  @Override
  public Block transform(Block block, RoundKey roundKey) {
    DesToCipherTransformationAdapter desCipherTransformation = new DesToCipherTransformationAdapter();
    return desCipherTransformation.transform(block, roundKey);

  }
}
