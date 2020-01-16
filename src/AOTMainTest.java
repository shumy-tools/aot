import java.security.NoSuchAlgorithmException;

import ieeta.aot.Authorization;
import ieeta.aot.Utils;
import ieeta.aot.node.NodeServer;
import ieeta.aot.node.NodeSession;
import ieeta.aot.terminal.Terminal;
import ieeta.aot.terminal.TerminalSession;

public class AOTMainTest {
  public static void main(String[] args) throws NoSuchAlgorithmException {
    final Terminal term = Utils.genTerminal();
    final NodeServer node = Utils.genNodeServer();
    
    // Assuming that terminal key and operator key is already certified by the node
    
    final TerminalSession tSession = term.genSession(node.pkey);
    final Authorization auth = tSession.authorize(data -> {
      System.out.println("Token: " + Utils.bytesToHex(data));
      System.out.println("SHA-256(Token): " + Utils.bytesToHex(Utils.hash(data)));
      
      // TODO: perform a Citizens Card signature on "data" -> "sigBytes"
      
      // return new ExtSignature(pubKey, sigBytes);
      return null;
    });
    
    // TODO: authorization is sent via network
    
    // TODO: in real applications both keys should be checked before binding the session (auth.termKey & auth.extSig.operKey)
    final NodeSession nSession = node.bindSession(auth, cdata -> {
      System.out.println("Token: " + Utils.bytesToHex(cdata.data));
      
      //TODO: check if "cdata.time" is in acceptable range
      //TODO: perform a Citizens Card signature check on "cdata.data" using "cdata.extSig"
      
      return true;
    });
    
    // TODO: encrypt and send data Ek[data]
    final byte[] ciphertext = nSession.encrypt("Testing sending data!".getBytes());
    
    // TODO: send Ek1[k2] when consent is confirmed
    tSession.setK(nSession.encK2);
    final byte[] plaintext = tSession.dencrypt(ciphertext);
    
    System.out.println(new String(plaintext));
  }
}