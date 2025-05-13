package com.crypto.cipher.transformation;

import com.crypto.util.datatypes.Block;
import com.crypto.util.datatypes.RoundKey;

public interface CipherTransformation {

  Block transform(Block block, RoundKey roundKey);

}
