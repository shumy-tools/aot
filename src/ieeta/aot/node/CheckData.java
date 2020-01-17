package ieeta.aot.node;

import ieeta.aot.AuthRequest.ExtSignature;

public class CheckData {
  public final long time;
  public final byte[] data;
  public final ExtSignature extSig;
  
  public CheckData(long time, byte[] data, ExtSignature extSig) {
    this.time = time;
    this.data = data;
    this.extSig = extSig;
  }
}
