package ieeta.aot;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import ieeta.aot.node.NodeServer;
import ieeta.aot.terminal.Terminal;
import net.i2p.crypto.eddsa.math.Curve;
import net.i2p.crypto.eddsa.math.Field;
import net.i2p.crypto.eddsa.math.FieldElement;
import net.i2p.crypto.eddsa.math.GroupElement;
import net.i2p.crypto.eddsa.math.ed25519.Ed25519FieldElement;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;

public class Utils {
  public static final EdDSANamedCurveSpec ed25519 = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
  public static final GroupElement basePoint = ed25519.getB();
  
  public static final Curve curve = ed25519.getCurve();
  public static final Field field = curve.getField();
  
  public static final SecureRandom random = new SecureRandom();
  
  public static Terminal genTerminal() {
    final FieldElement skey = getRandomFieldElement();
    return new Terminal(skey);
  }
  
  public static NodeServer genNodeServer() {
    final FieldElement skey = getRandomFieldElement();
    return new NodeServer(skey);
  }
  
  public static String bytesToHex(byte[] a) {
    final StringBuilder sb = new StringBuilder(a.length * 2);
    for(byte b: a)
       sb.append(String.format("%02x", b));
    return sb.toString();
  }
  
  public static byte[] longToBytes(long x) {
    final ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
    buffer.putLong(x);
    return buffer.array();
  }
  
  public static long bytesToLong(byte[] bytes) {
    final ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
    buffer.put(bytes);
    buffer.flip();
    return buffer.getLong();
  }
  
  public static FieldElement getRandomFieldElement() {
    final int[] t = new int[10];
    for (int j=0; j<10; j++) {
      t[j] = random.nextInt(1 << 25) - (1 << 24);
    }
    
    return new Ed25519FieldElement(field, t);
  }
  
  public static byte[] ecdh(FieldElement secret, GroupElement pkey) {
    final GroupElement key = pkey.scalarMultiply(secret.toByteArray());
    try {
      final MessageDigest digest = MessageDigest.getInstance("SHA-256");
      digest.update(key.toByteArray());
      return digest.digest();
    } catch (Throwable e) {
      e.printStackTrace();
      throw new RuntimeException("Error on ecdh!");
    }
  }
  
  public static byte[] encrypt(byte[] secret, byte[] plaintext) {
    try {
      final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      final SecretKeySpec key = new SecretKeySpec(secret, "AES");
      
      final byte[] ivBytes = new byte[cipher.getBlockSize()];
      Utils.random.nextBytes(ivBytes);
      final IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
      
      cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
      final byte[] ciphertext = cipher.doFinal(plaintext);
      
      byte[] extCiphertext = new byte[ivBytes.length + ciphertext.length];
      System.arraycopy(ivBytes, 0, extCiphertext, 0, ivBytes.length);
      System.arraycopy(ciphertext, 0, extCiphertext, ivBytes.length, ciphertext.length);
      
      return extCiphertext;
    } catch (Throwable e) {
      e.printStackTrace();
      throw new RuntimeException("Error on encrypt!");
    }
  }
  
  public static byte[] dencrypt(byte[] secret, byte[] extCiphertext) {
    try {
      final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      final SecretKeySpec key = new SecretKeySpec(secret, "AES");
      
      final byte[] ivBytes = new byte[cipher.getBlockSize()];
      System.arraycopy(extCiphertext, 0, ivBytes, 0, ivBytes.length);
      final IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
      
      final byte[] ciphertext = new byte[extCiphertext.length - ivBytes.length];
      System.arraycopy(extCiphertext, ivBytes.length, ciphertext, 0, ciphertext.length);
      
      cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
      return cipher.doFinal(ciphertext);
    } catch (Throwable e) {
      e.printStackTrace();
      throw new RuntimeException("Error on dencrypt!");
    }
  }
}
