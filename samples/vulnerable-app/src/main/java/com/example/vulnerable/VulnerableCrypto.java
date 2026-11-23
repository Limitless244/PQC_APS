package com.example.vulnerable;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.util.Random;

/**
 * Deliberately vulnerable sample application demonstrating legacy/insecure cryptography.
 */
public class VulnerableCrypto {

    // VULN: Hardcoded API Secret
    private static final String API_SECRET_KEY = "DUMMY_SECRET_KEY_1234567890_EXAMP";

    public static void main(String[] args) throws Exception {
        // VULN: RSA 1024-bit (Shor vulnerable + classically factorable)
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(1024);
        KeyPair rsaPair = rsaGen.generateKeyPair();

        // VULN: MD5 message digest
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        byte[] md5Hash = md5.digest("test data".getBytes());

        // VULN: DES cipher
        Cipher desCipher = Cipher.getInstance("DES/CBC/PKCS5Padding");

        // VULN: AES in ECB mode
        Cipher ecbCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

        // VULN: AES-128 key size
        KeyGenerator aesGen = KeyGenerator.getInstance("AES");
        aesGen.init(128);
        SecretKey aes128Key = aesGen.generateKey();

        // VULN: Insecure RNG for cryptographic key generation
        Random insecureRandom = new Random();
        byte[] sessionKey = new byte[16];
        insecureRandom.nextBytes(sessionKey);

        // VULN: Static/zero IV with GCM
        Cipher gcmCipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] staticIv = new byte[12];
        GCMParameterSpec spec = new GCMParameterSpec(128, staticIv);
        gcmCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(sessionKey, "AES"), spec);
    }
}
