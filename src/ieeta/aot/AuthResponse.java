package ieeta.aot;

import java.io.Serializable;

public class AuthResponse implements Serializable {
  private static final long serialVersionUID = 1L;
  
  public final byte[] nodePen;
  public final byte[] nodeSig;
  
  public AuthResponse(byte[] nodePen, byte[] nodeSig) {
    this.nodePen = nodePen;
    this.nodeSig = nodeSig;
  }
}
