import ieeta.aot.Authorization;
import ieeta.aot.Utils;
import ieeta.aot.node.NodeServer;
import ieeta.aot.terminal.Terminal;
import ieeta.aot.terminal.TerminalSession;

public class AOTMainTest {
  public static void main(String[] args) {
    final Terminal term = Utils.genTerminal();
    final NodeServer node = Utils.genNodeServer();
    
    final TerminalSession session = term.genSession(node.pkey);
    final Authorization auth = session.authorize();
    
    node.bindSession(auth);
  }
}