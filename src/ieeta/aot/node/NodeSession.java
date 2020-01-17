package ieeta.aot.node;

import ieeta.aot.AuthResponse;
import ieeta.aot.EncryptedData;
import ieeta.aot.Utils;

public class NodeSession {
  private final byte[] k;
  public final AuthResponse resp;
  
  NodeSession(byte[] k, byte[] nodePen, byte[] nodeSig) {
    this.k = k;
    this.resp = new AuthResponse(nodePen, nodeSig);
  }
  
  public EncryptedData encrypt(byte[] cleartext) {
    final byte[] d = Utils.genRandomFieldElement().toByteArray();
    return Utils.encrypt(this.k, d, cleartext);
  }
}
