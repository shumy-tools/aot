package ieeta.aot.node;

import ieeta.aot.Utils;

public class NodeSession {
  private final byte[] k;
  public final byte[] encK2;
  
  public NodeSession(byte[] k, byte[] encK2) {
    this.k = k;
    this.encK2 = encK2;
  }
  
  public byte[] encrypt(byte[] cleartext) {
    return Utils.encrypt(this.k, cleartext);
  }
}
