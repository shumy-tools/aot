package ieeta.aot;

public class Authorization {
  public static class ExtSignature {
    public final byte[] operKey;
    public final byte[] sig;
    
    public ExtSignature(byte[] operKey, byte[] sig) {
      this.operKey = operKey;
      this.sig = sig;
    }
  }
  
  public final byte[] termKey;
  public final byte[] token;
  public final ExtSignature extSig;
  
  public Authorization(byte[] termKey, byte[] token, ExtSignature extSig) {
    this.termKey = termKey;
    this.token = token;
    this.extSig = extSig;
  }
}