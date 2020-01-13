package ieeta.aot.terminal;

import ieeta.aot.Utils;
import net.i2p.crypto.eddsa.math.FieldElement;
import net.i2p.crypto.eddsa.math.GroupElement;

public class Terminal {
  final FieldElement skey;
  public final GroupElement pkey;
  
  public Terminal(FieldElement skey) {
    this.skey = skey;
    
    final GroupElement preKey = Utils.basePoint.scalarMultiply(skey.toByteArray());
    this.pkey = Utils.curve.createPoint(preKey.toByteArray(), true);
  }
  
  public TerminalSession genSession(GroupElement nodeKey) {
    final FieldElement rField = Utils.getRandomFieldElement();
    
    // H(r.t.Pn) -> k1
    final GroupElement key = Utils.curve.createPoint(nodeKey.scalarMultiply(skey.toByteArray()).toByteArray(), true);
    final byte[] k1 = Utils.ecdh(rField, key);
    
    // H(t.Pn) -> s
    final byte[] secret = Utils.ecdh(skey, nodeKey);
    
    // [r, time]
    final byte[] rBytes = rField.toByteArray();
    final byte[] timeBytes = Utils.longToBytes(System.currentTimeMillis());
    byte[] plaintext = new byte[rBytes.length + timeBytes.length];
    System.arraycopy(rBytes, 0, plaintext, 0, rBytes.length);
    System.arraycopy(timeBytes, 0, plaintext, rBytes.length, timeBytes.length);
    
    // <iv, Es[r, time]>
    final byte[] token = Utils.encrypt(secret, plaintext);
    //System.out.println("T r: " + rField);
    
    return new TerminalSession(this.pkey.toByteArray(), token, k1);
  }
}
