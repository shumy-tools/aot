package ieeta.aot.terminal;

import java.math.BigInteger;

import ieeta.aot.Authorization;
import ieeta.aot.Utils;

public class TerminalSession {
  private final byte[] termKey;
  private final byte[] token;
  private final byte[] k1;
  
  TerminalSession(byte[] termKey, byte[] token, byte[] k1) {
    this.termKey = termKey;
    this.token = token;
    this.k1 = k1;
    
    System.out.println(Utils.bytesToHex(k1));
  }
  
  public Authorization authorize() {
    //TODO: implement CC signature
    return new Authorization(this.termKey, this.token);
  }
}
