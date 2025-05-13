package com.crypto.cipher.keyexpansion;

import com.crypto.util.datatypes.Key;
import com.crypto.util.datatypes.RoundKey;

public interface KeyExpansion {

  public RoundKey[] generateRoundKeys(Key key);

}
