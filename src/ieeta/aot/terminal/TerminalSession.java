package ieeta.aot.terminal;

import java.security.PublicKey;

import ieeta.aot.AuthRequest;
import ieeta.aot.AuthRequest.ExtSignature;
import ieeta.aot.AuthResponse;
import ieeta.aot.EncryptedData;
import ieeta.aot.Utils;
import net.i2p.crypto.eddsa.math.FieldElement;
import net.i2p.crypto.eddsa.math.GroupElement;

public class TerminalSession {
  private byte[] k = null;
  private final FieldElement et;
  public final AuthRequest req;
  
  TerminalSession(FieldElement et, byte[] token, byte[] termKey, byte[] termSig, ExtSignature extSig) {
    this.et = et;
    this.req = new AuthRequest(token, termKey, termSig, extSig);
  }
  
  public void setK(PublicKey nodeKey, AuthResponse resp) {
    if (k != null) {
      throw new RuntimeException("k already set!");
    }
    
    if (!Utils.sigVerify(nodeKey, resp.nodePen, resp.nodeSig)) {
      throw new RuntimeException("Invalid node signature!");
    }
    
    // TODO: check if Pen is in the group E(F)!
    final GroupElement Pen = Utils.curve.createPoint(resp.nodePen, true);
    
    // H(et x Pen) -> k
    this.k = Utils.ecdh(et, Pen);
  }
  
  public byte[] dencrypt(EncryptedData ciphertext) {
    if (k == null) {
      throw new RuntimeException("k is not set!");
    }
    
    return Utils.dencrypt(this.k, ciphertext);
  }
}
