package ieeta.aot;

public class Authorization {
  public final byte[] termKey;
  public final byte[] token;
  public final byte[] sig;
  
  public Authorization(byte[] termKey, byte[] token, byte[] sig) {
    this.termKey = termKey;
    this.token = token;
    this.sig = sig;
  }
}