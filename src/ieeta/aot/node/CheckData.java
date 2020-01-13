package ieeta.aot.node;

public class CheckData {
  public final long time;
  public final byte[] data;
  public final byte[] sig;
  
  public CheckData(long time, byte[] data, byte[] sig) {
    this.time = time;
    this.data = data;
    this.sig = sig;
  }
}
