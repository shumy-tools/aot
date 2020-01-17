package ieeta.aot;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import ieeta.aot.node.NodeServer;
import ieeta.aot.terminal.Terminal;
import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.math.Curve;
import net.i2p.crypto.eddsa.math.Field;
import net.i2p.crypto.eddsa.math.FieldElement;
import net.i2p.crypto.eddsa.math.GroupElement;
import net.i2p.crypto.eddsa.math.ed25519.Ed25519FieldElement;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

public class Utils {
  public static final EdDSANamedCurveSpec ed25519 = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
  public static final GroupElement basePoint = ed25519.getB();
  
  public static final Curve curve = ed25519.getCurve();
  public static final Field field = curve.getField();
  
  public static final SecureRandom random = new SecureRandom();
  
  public static Terminal genTerminal() {
    final PrivateKey skey = Utils.genRandomPrivateKey();
    return new Terminal(skey);
  }
  
  public static NodeServer genNodeServer() {
    final PrivateKey skey = Utils.genRandomPrivateKey();
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
  
  public static FieldElement genRandomFieldElement() {
    final int[] t = new int[10];
    for (int j=0; j<10; j++) {
      t[j] = random.nextInt(1 << 25) - (1 << 24);
    }
    
    return new Ed25519FieldElement(field, t);
  }
  
  public static PrivateKey genRandomPrivateKey() {
    final byte[] seed = new byte[field.getb()/8];
    random.nextBytes(seed);
    
    final EdDSAPrivateKeySpec privKey = new EdDSAPrivateKeySpec(seed, ed25519);
    return new EdDSAPrivateKey(privKey);
  }
  
  public static PublicKey genPublicKey(PrivateKey secret) {
    final EdDSAPrivateKey privKey = (EdDSAPrivateKey) secret;
    
    final EdDSAPublicKeySpec pubKey = new EdDSAPublicKeySpec(privKey.getA(), ed25519);
    return new EdDSAPublicKey(pubKey);
  }
  
  public static GroupElement genPublicKey(FieldElement secret) {
    final GroupElement preKey = Utils.basePoint.scalarMultiply(secret.toByteArray());
    return Utils.curve.createPoint(preKey.toByteArray(), true);
  }
  
  public static PublicKey decodePublicKey(byte[] encoded) {
    final X509EncodedKeySpec x509 = new X509EncodedKeySpec(encoded);
    try {
      return new EdDSAPublicKey(x509);
    } catch (Throwable e) {
      e.printStackTrace();
      throw new RuntimeException("Error on decodePublicKey!");
    }
  }
  
  public static byte[] hash(byte[] data) {
    try {
      final MessageDigest digest = MessageDigest.getInstance("SHA-256");
      return digest.digest(data);
    } catch (Throwable e) {
      e.printStackTrace();
      throw new RuntimeException("Error on hash!");
    }
  }
  
  public static byte[] ecdh(FieldElement secret, GroupElement pkey) {
    final GroupElement key = pkey.scalarMultiply(secret.toByteArray());
    return hash(key.toByteArray());
  }
  
  public static byte[] sign(PrivateKey secret, byte[] msg) {
    try {
      final Signature sgr = new EdDSAEngine(MessageDigest.getInstance(ed25519.getHashAlgorithm()));
      sgr.setParameter(EdDSAEngine.ONE_SHOT_MODE);
      sgr.initSign(secret);
      sgr.update(msg);
      return sgr.sign();
    } catch (Throwable e) {
      e.printStackTrace();
      throw new RuntimeException("Error on sign!");
    }
  }
  
  public static boolean sigVerify(PublicKey key, byte[] msg, byte[] sig) {
    try {
      final Signature sgr = new EdDSAEngine(MessageDigest.getInstance(ed25519.getHashAlgorithm()));
      sgr.setParameter(EdDSAEngine.ONE_SHOT_MODE);
      sgr.initVerify(key);
      sgr.update(msg);
      return sgr.verify(sig);
    } catch (Throwable e) {
      e.printStackTrace();
      return false;
    }
  }
  
  public static EncryptedData encrypt(byte[] k, byte[] d, byte[] plaintext) {
    try {
      // encrypt data
      final SecretKeySpec dataKey = new SecretKeySpec(d, "AES");
      final Cipher cipherData = Cipher.getInstance("AES/CBC/PKCS5Padding");
      
      final byte[] ivBytes = new byte[cipherData.getBlockSize()];
      Utils.random.nextBytes(ivBytes);
      
      final IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
      cipherData.init(Cipher.ENCRYPT_MODE, dataKey, ivSpec);
      final byte[] ciphertext = cipherData.doFinal(plaintext);
      
      // encrypt key
      final SecretKeySpec keyKey = new SecretKeySpec(k, "AES");
      final Cipher cipherKey = Cipher.getInstance("AES/ECB/PKCS5Padding");
      cipherKey.init(Cipher.ENCRYPT_MODE, keyKey);
      final byte[] encD = cipherKey.doFinal(d);
      
      return new EncryptedData(ivBytes, ciphertext, encD);
    } catch (Throwable e) {
      e.printStackTrace();
      throw new RuntimeException("Error on encrypt!");
    }
  }
  
  public static byte[] dencrypt(byte[] k, EncryptedData ciphertext) {
    try {
      // dencrypt key
      final SecretKeySpec keyKey = new SecretKeySpec(k, "AES");
      final Cipher cipherKey = Cipher.getInstance("AES/ECB/PKCS5Padding");
      cipherKey.init(Cipher.DECRYPT_MODE, keyKey);
      final byte[] d = cipherKey.doFinal(ciphertext.encD);
      
      // dencrypt data
      final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      final SecretKeySpec dataKey = new SecretKeySpec(d, "AES");
      
      final IvParameterSpec ivSpec = new IvParameterSpec(ciphertext.iv);
      cipher.init(Cipher.DECRYPT_MODE, dataKey, ivSpec);
      return cipher.doFinal(ciphertext.data);
    } catch (Throwable e) {
      e.printStackTrace();
      throw new RuntimeException("Error on dencrypt!");
    }
  }
}
