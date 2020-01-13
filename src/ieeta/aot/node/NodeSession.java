package ieeta.aot.node;

import ieeta.aot.Utils;

public class NodeSession {
  private final byte[] k1;
  
  public NodeSession(byte[] k1) {
    this.k1 = k1;
    System.out.println(Utils.bytesToHex(k1));
  }
}
