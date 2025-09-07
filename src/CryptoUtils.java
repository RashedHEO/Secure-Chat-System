import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.Base64;

public class CryptoUtils {

    // توليد KeyPair ثابت لكل طرف
    public static KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    // توليد AES Key عشوائي
    public static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        return keyGen.generateKey();
    }

    // توليد Nonce عشوائي
    public static byte[] generateNonce() {
        byte[] nonce = new byte[12];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    // تشفير AES-GCM
    public static byte[] encryptAES(byte[] data, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        return cipher.doFinal(data);
    }

    // فك تشفير AES-GCM
    public static byte[] decryptAES(byte[] data, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        return cipher.doFinal(data);
    }

    // كتابة Log مشفر على القرص
    public static void writeEncryptedLog(Path path, String content, SecretKey key) throws Exception {
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        byte[] encrypted = encryptAES(content.getBytes(StandardCharsets.UTF_8), key, iv);
        byte[] combined = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);
        Files.write(path, combined, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
    }

    // قراءة Log مشفر من القرص
    public static String readEncryptedLog(Path path, SecretKey key) throws Exception {
        byte[] combined = Files.readAllBytes(path);
        byte[] iv = new byte[12];
        byte[] data = new byte[combined.length - 12];
        System.arraycopy(combined, 0, iv, 0, 12);
        System.arraycopy(combined, 12, data, 0, data.length);
        byte[] decrypted = decryptAES(data, key, iv);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    // توقيع رقمي للرسائل
    public static byte[] sign(PrivateKey privateKey, byte[] data) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    // التحقق من التوقيع الرقمي
    public static boolean verify(PublicKey publicKey, byte[] data, byte[] sig) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(sig);
    }
}
