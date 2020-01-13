package ieeta.aot;

public class Authorization {
  public final byte[] termKey;
  public final byte[] token;
  
  public Authorization(byte[] termKey, byte[] token) {
    this.termKey = termKey;
    this.token = token;
    //TODO: add CC signature
  }
}