package ieeta.aot;

import java.io.Serializable;

public class EncryptedData implements Serializable {
  private static final long serialVersionUID = 1L;
  
  public final byte[] iv;
  public final byte[] data;
  public final byte[] encD;
  
  public EncryptedData(byte[] iv, byte[] data, byte[] encD) {
    this.iv = iv;
    this.data = data;
    this.encD = encD;
  }
}
