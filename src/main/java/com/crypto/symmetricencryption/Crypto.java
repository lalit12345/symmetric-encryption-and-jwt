package com.crypto.symmetricencryption;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.stereotype.Service;

@Service
public class Crypto {

  public String generateSecretKeyWithoutBaseKey() throws NoSuchAlgorithmException {

    KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
    keyGenerator.init(256);

    SecretKey secretKeyWithoutBaseKey = keyGenerator.generateKey();

    return Base64.getEncoder().encodeToString(secretKeyWithoutBaseKey.getEncoded());
  }

  public String generateSecretKeyWithBaseKey(String inputKeyPart) throws NoSuchAlgorithmException {

    String currentTime = LocalDateTime.now().toString();

    String baseKey = inputKeyPart + "-" + currentTime;

    SecureRandom secureRandom = new SecureRandom();

    secureRandom.setSeed(baseKey.getBytes());

    KeyGenerator kgen = KeyGenerator.getInstance("AES");
    kgen.init(256, secureRandom);

    SecretKey secretKeyWithBaseKey = kgen.generateKey();

    byte[] encodedFormat = secretKeyWithBaseKey.getEncoded();

    SecretKeySpec key = new SecretKeySpec(encodedFormat, "AES");

    return Base64.getEncoder().encodeToString(key.getEncoded());
  }

  public String encrypt(String plainText, String secretKeyString) throws NoSuchAlgorithmException,
      NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

    Cipher cipher = Cipher.getInstance("AES");

    byte[] decodedKey = Base64.getDecoder().decode(secretKeyString);
    SecretKey secretKey = new SecretKeySpec(decodedKey, "AES");

    byte[] plainTextByte = plainText.getBytes(StandardCharsets.UTF_8);

    cipher.init(Cipher.ENCRYPT_MODE, secretKey);

    byte[] encryptedBytes = cipher.doFinal(plainTextByte);

    return Base64.getEncoder().encodeToString(encryptedBytes);
  }

  public String decrypt(String encodedString, String secretKeyString)
      throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
      BadPaddingException, InvalidKeyException {

    Cipher cipher = Cipher.getInstance("AES");

    byte[] decodedKey = Base64.getDecoder().decode(secretKeyString);
    SecretKey secretKey = new SecretKeySpec(decodedKey, "AES");

    byte[] encryptedBytes = Base64.getDecoder().decode(encodedString);

    cipher.init(Cipher.DECRYPT_MODE, secretKey);
    byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

    return new String(decryptedBytes, StandardCharsets.UTF_8);
  }

}
