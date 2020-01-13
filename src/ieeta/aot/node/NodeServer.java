package ieeta.aot.node;

import ieeta.aot.Authorization;
import ieeta.aot.Utils;
import net.i2p.crypto.eddsa.math.FieldElement;
import net.i2p.crypto.eddsa.math.GroupElement;

public class NodeServer {
  final FieldElement skey;
  public final GroupElement pkey;
  
  public NodeServer(FieldElement skey) {
    this.skey = skey;
    
    final GroupElement preKey = Utils.basePoint.scalarMultiply(skey.toByteArray());
    this.pkey = Utils.curve.createPoint(preKey.toByteArray(), true);
  }
  
  public NodeSession bindSession(Authorization auth) {
    // H(n.Pt) -> s
    final GroupElement termKey = Utils.curve.createPoint(auth.termKey, true);
    final byte[] secret = Utils.ecdh(skey, termKey);
    
    // [r, time]
    final byte[] plaintext = Utils.dencrypt(secret, auth.token);
    final byte[] rBytes = new byte[plaintext.length - Long.BYTES];
    final byte[] timeBytes = new byte[Long.BYTES];
    System.arraycopy(plaintext, 0, rBytes, 0, rBytes.length);
    System.arraycopy(plaintext, rBytes.length, timeBytes, 0, timeBytes.length);
    
    final FieldElement rField = Utils.field.fromByteArray(rBytes);
    final long time = Utils.bytesToLong(timeBytes);
    
    //System.out.println("N r: " + rField);
    //TODO: check time
    
    // H(r.n.Pt) -> k1
    final GroupElement key = Utils.curve.createPoint(termKey.scalarMultiply(skey.toByteArray()).toByteArray(), true);
    final byte[] k1 = Utils.ecdh(rField, key);
    
    return new NodeSession(k1);
  }
}
