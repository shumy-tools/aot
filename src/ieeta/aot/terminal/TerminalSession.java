package ieeta.aot.terminal;

import ieeta.aot.Authorization;
import net.i2p.crypto.eddsa.math.FieldElement;
import net.i2p.crypto.eddsa.math.GroupElement;

public class TerminalSession {
  private final Terminal term;
  private final FieldElement r;
  private final GroupElement nodeKey;
  
  //private final Authorization.Data data;
  
  TerminalSession(Terminal term, FieldElement r, GroupElement nodeKey) {
    this.term = term;
    this.r = r;
    this.nodeKey = nodeKey;
    
    //TODO: encrypt En.t[r,time,H.]
  }
  
  public Authorization authorize() {
    //TODO: implement
    return null;
  }
}
