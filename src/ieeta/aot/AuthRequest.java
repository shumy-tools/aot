package ieeta.aot;

import java.io.Serializable;

public class AuthRequest implements Serializable {
  private static final long serialVersionUID = 1L;

  public static class ExtSignature {
    public final byte[] operKey;
    public final byte[] sig;
    
    public ExtSignature(byte[] operKey, byte[] sig) {
      this.operKey = operKey;
      this.sig = sig;
    }
  }
  
  public final byte[] token;
  public final byte[] termKey;
  public final byte[] termSig;
  public final ExtSignature extSig;
  
  public AuthRequest(byte[] token, byte[] termKey, byte[] termSig, ExtSignature extSig) {
    this.token = token;
    this.termKey = termKey;
    this.termSig = termSig;
    this.extSig = extSig;
  }
}