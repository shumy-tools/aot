package ieeta.aot.terminal;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.function.Function;

import ieeta.aot.Utils;
import ieeta.aot.AuthRequest.ExtSignature;
import net.i2p.crypto.eddsa.math.FieldElement;
import net.i2p.crypto.eddsa.math.GroupElement;

public class Terminal {
  final PrivateKey skey;
  public final PublicKey pkey;
  
  public Terminal(PrivateKey skey) {
    this.skey = skey;
    this.pkey = Utils.genPublicKey(skey);
  }
  
  public TerminalSession genSession(Function<byte[], ExtSignature> sigFunc) {
    final byte[] termKey = this.pkey.getEncoded();
    
    // et x G -> Pet
    final FieldElement et = Utils.genRandomFieldElement();
    final GroupElement Pet = Utils.genPublicKey(et);
    
    // [Pet, time]
    final byte[] PetBytes = Pet.toByteArray();
    final byte[] timeBytes = Utils.longToBytes(System.currentTimeMillis());
    final byte[] token = new byte[PetBytes.length + timeBytes.length];
    System.arraycopy(PetBytes, 0, token, 0, PetBytes.length);
    System.arraycopy(timeBytes, 0, token, PetBytes.length, timeBytes.length);
    
    // Sig_t<Pet, time>
    final byte[] termSig = Utils.sign(skey, token);
    
    // Sig_o<Pt, Sig_t>
    final byte[] data = new byte[termKey.length + termSig.length];
    System.arraycopy(termKey, 0, data, 0, termKey.length);
    System.arraycopy(termSig, 0, data, termKey.length, termSig.length);
    
    final ExtSignature extSig = sigFunc.apply(data);
    
    return new TerminalSession(et, token, termKey, termSig, extSig);
  }
}
