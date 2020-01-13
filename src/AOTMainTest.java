import ieeta.aot.Authorization;
import ieeta.aot.Utils;
import ieeta.aot.node.NodeServer;
import ieeta.aot.node.NodeSession;
import ieeta.aot.terminal.Terminal;
import ieeta.aot.terminal.TerminalSession;

public class AOTMainTest {
  public static void main(String[] args) {
    final Terminal term = Utils.genTerminal();
    final NodeServer node = Utils.genNodeServer();
    
    final TerminalSession tSession = term.genSession(node.pkey);
    final Authorization auth = tSession.authorize(data -> {
      System.out.println(Utils.bytesToHex(data));
      //TODO: perform CC signature on data
      return null;
    });
    
    //TODO: authorization is sent via network
    
    final NodeSession nSession = node.bindSession(auth, cdata -> {
      System.out.println(Utils.bytesToHex(cdata.data));
      //TODO: perform a CC signature check and timestamp
      return true;
    });
    
    //TODO: encrypt and send data Ek[data]
    final byte[] ciphertext = nSession.encrypt("Testing sending data!".getBytes());
    
    //TODO: send Ek1[k2] when consent is confirmed
    tSession.setK(nSession.encK2);
    final byte[] plaintext = tSession.dencrypt(ciphertext);
    
    System.out.println(new String(plaintext));
  }
}