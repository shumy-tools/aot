package ieeta.aot.terminal;

import net.i2p.crypto.eddsa.math.FieldElement;
import net.i2p.crypto.eddsa.math.GroupElement;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;

public class Terminal {
  private static final EdDSANamedCurveSpec ed25519 = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
  private static final GroupElement basePoint = ed25519.getB();
  
  final FieldElement skey;
  final GroupElement pkey;
  
  Terminal(FieldElement skey) {
    this.skey = skey;
    this.pkey = basePoint.scalarMultiply(skey.toByteArray());
  }
  
  public TerminalSession genSession(GroupElement nodeKey) {
    final FieldElement r = TerminalFactory.getRandomFieldElement();
    
    return new TerminalSession(this, r, nodeKey);
  }
}
