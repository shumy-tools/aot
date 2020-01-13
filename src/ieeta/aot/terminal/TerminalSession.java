package ieeta.aot.terminal;

import java.util.function.Function;

import ieeta.aot.Authorization;
import ieeta.aot.Utils;

public class TerminalSession {
  private final byte[] termKey;
  private final byte[] token;
  private final byte[] k1;
  
  private byte[] k = null;
  
  TerminalSession(byte[] termKey, byte[] token, byte[] k1) {
    this.termKey = termKey;
    this.token = token;
    this.k1 = k1;
  }
  
  public Authorization authorize(Function<byte[], byte[]> sigFunc) {
    final byte[] data = new byte[termKey.length + token.length];
    System.arraycopy(termKey, 0, data, 0, termKey.length);
    System.arraycopy(token, 0, data, 0, token.length);
    
    final byte[] sig = sigFunc.apply(data);
    return new Authorization(this.termKey, this.token, sig);
  }
  
  public void setK(byte[] encK2) {
    if (k != null) {
      throw new RuntimeException("k already set!");
    }
    
    final byte[] k2 = Utils.dencrypt(k1, encK2);
    this.k = Utils.bytesXOR(k1, k2);
  }
  
  public byte[] dencrypt(byte[] ciphertext) {
    if (k == null) {
      throw new RuntimeException("k is not set!");
    }
    
    return Utils.dencrypt(this.k, ciphertext);
  }
}
