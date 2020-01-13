package ieeta.aot.node;

import java.util.function.Function;

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
  
  public NodeSession bindSession(Authorization auth, Function<CheckData, Boolean> checkFunc) {
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
    
    // check data
    final byte[] data = new byte[auth.termKey.length + auth.token.length];
    System.arraycopy(auth.termKey, 0, data, 0, auth.termKey.length);
    System.arraycopy(auth.token, 0, data, 0, auth.token.length);
    
    final CheckData cdata = new CheckData(time, data, auth.sig);
    if (!checkFunc.apply(cdata)) {
      throw new RuntimeException("Authorization failed!");
    }
    
    // H(r.n.Pt) -> k1
    final GroupElement key = Utils.curve.createPoint(termKey.scalarMultiply(skey.toByteArray()).toByteArray(), true);
    final byte[] k1 = Utils.ecdh(rField, key);
    
    // Ek1[k2]
    final byte[] k2 = Utils.getRandomFieldElement().toByteArray();
    final byte[] encK2 = Utils.encrypt(k1, k2);
    
    // k1 XOR k2 = k
    final byte[] k = Utils.bytesXOR(k1, k2);
    
    return new NodeSession(k, encK2);
  }
}
