package com.crypto.symmetricencryption;

import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@SpringBootApplication
public class SymmetricEncryptionApplication implements CommandLineRunner {

  @Autowired
  private JJWTService jwtService;

  @Autowired
  private JWTAuth0Service jwtAuth0Service;

  @Autowired
  private Crypto crypto;

  public static void main(String[] args) {
    SpringApplication.run(SymmetricEncryptionApplication.class, args).close();
  }

  @Override
  public void run(String... args) throws Exception {

    log.info("========= " + new MimeTypeConstants().getMimeType("xml"));

    String metadata = "some-metadata-string";

    String secretKeyString = crypto.generateSecretKeyWithBaseKey(UUID.randomUUID().toString());
    
    log.info("======== " + secretKeyString + " ========");

    // generate token using jjwt
    String jwtTokenByJJwt = jwtService.createJwt(secretKeyString, metadata);

    jwtService.decodeJwtToken(secretKeyString, jwtTokenByJJwt);

    log.info("===========================================================================");

    // generate token using auth0
    String jwttokenByAuth0 = jwtAuth0Service.createJwt(secretKeyString);

    jwtAuth0Service.decodeJwtToken(secretKeyString, jwttokenByAuth0);
  }
}
