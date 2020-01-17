package ieeta.aot.node;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.function.Function;

import ieeta.aot.AuthRequest;
import ieeta.aot.Utils;
import net.i2p.crypto.eddsa.math.FieldElement;
import net.i2p.crypto.eddsa.math.GroupElement;

public class NodeServer {
  final PrivateKey skey;
  public final PublicKey pkey;
  
  public NodeServer(PrivateKey skey) {
    this.skey = skey;
    this.pkey = Utils.genPublicKey(skey);
  }
  
  public NodeSession bindSession(AuthRequest auth, Function<CheckData, Boolean> checkFunc) {
    // check Sig_t<Pet, time>
    final PublicKey termKey = Utils.decodePublicKey(auth.termKey);
    if (!Utils.sigVerify(termKey, auth.token, auth.termSig)) {
      throw new RuntimeException("Invalid terminal signature!");
    }
    
    // decode [Pet, time]
    final byte[] PetBytes = new byte[auth.token.length - Long.BYTES];
    final byte[] timeBytes = new byte[Long.BYTES];
    System.arraycopy(auth.token, 0, PetBytes, 0, PetBytes.length);
    System.arraycopy(auth.token, PetBytes.length, timeBytes, 0, timeBytes.length);
    
    // TODO: check if Pet is in the group E(F)!
    final GroupElement Pet = Utils.curve.createPoint(PetBytes, true);
    final long time = Utils.bytesToLong(timeBytes);
    
    // check Sig_o<Pt, Sig_t>
    final byte[] data = new byte[auth.termKey.length + auth.termSig.length];
    System.arraycopy(auth.termKey, 0, data, 0, auth.termKey.length);
    System.arraycopy(auth.termSig, 0, data, auth.termKey.length, auth.termSig.length);
    
    final CheckData cdata = new CheckData(time, data, auth.extSig);
    if (!checkFunc.apply(cdata)) {
      throw new RuntimeException("Authorization failed!");
    }
    
    // en x G -> Pen
    final FieldElement en = Utils.genRandomFieldElement();
    final byte[] PenBytes =  Utils.genPublicKey(en).toByteArray();
    
    // H(en x Pet) -> k
    final byte[] k = Utils.ecdh(en, Pet);
    
    final byte[] sig = Utils.sign(skey, PenBytes);
    return new NodeSession(k, PenBytes, sig);
  }
}
