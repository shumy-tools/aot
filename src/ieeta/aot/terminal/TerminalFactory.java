package ieeta.aot.terminal;

import java.security.SecureRandom;

import net.i2p.crypto.eddsa.Utils;
import net.i2p.crypto.eddsa.math.Field;
import net.i2p.crypto.eddsa.math.FieldElement;
import net.i2p.crypto.eddsa.math.ed25519.Ed25519FieldElement;
import net.i2p.crypto.eddsa.math.ed25519.Ed25519LittleEndianEncoding;

public class TerminalFactory {
  private static final SecureRandom random = new SecureRandom();
  
  public static Terminal generate() {
    final FieldElement skey = getRandomFieldElement();
    
    return new Terminal(skey);
  }
  
  public static Field getField() {
    return new Field(256, Utils.hexToBytes("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), new Ed25519LittleEndianEncoding());
  }
  
  public static FieldElement getRandomFieldElement() {
    final int[] t = new int[10];
    for (int j=0; j<10; j++) {
      t[j] = random.nextInt(1 << 25) - (1 << 24);
    }
    
    return new Ed25519FieldElement(getField(), t);
  }
}
