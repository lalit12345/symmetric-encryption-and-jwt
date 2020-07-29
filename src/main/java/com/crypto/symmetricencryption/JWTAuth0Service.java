package com.crypto.symmetricencryption;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.concurrent.TimeUnit;
import org.springframework.stereotype.Service;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class JWTAuth0Service {

  public String createJwt(String secretKeyString) {

    Algorithm algorithm = Algorithm.HMAC256(secretKeyString);

    long currentTimeMillis = System.currentTimeMillis();
    Date now = new Date(currentTimeMillis);

    String token = JWT.create().withIssuedAt(now).withIssuer("HS").sign(algorithm);

    log.info("Token has been generated using Auth0: {}", token);

    return token;
  }

  public String decodeJwtToken(String secretKeyString, String token) {

    Algorithm algorithm = Algorithm.HMAC256(secretKeyString);

    JWTVerifier verifier = JWT.require(algorithm).acceptLeeway(5).build();

    DecodedJWT decodedJWT = verifier.verify(token);

//    long now = System.currentTimeMillis();
    
    long now = Date.from(LocalDateTime.now().toInstant(ZoneOffset.UTC)).getTime();
    
    Date issuedAt = decodedJWT.getIssuedAt();

    log.info(String.valueOf(new Date(now)));

    log.info(issuedAt.toString());

    long differenceInMillies = Math.abs(now - issuedAt.getTime());
    int differenceInSeconds =
        Math.toIntExact(TimeUnit.SECONDS.convert(differenceInMillies, TimeUnit.MILLISECONDS));

    String data = null;
    if (differenceInSeconds > 30) {

      log.info("The Token has expired");

    } else {

      data = decodedJWT.getIssuer();

      log.info("Data after token has been decoded using Auth0: {}", data);
    }

    return data;
  }

  public static void main(String[] args) {

    JWTAuth0Service auth0Service = new JWTAuth0Service();

    auth0Service.createJwt("4DNGKyfLQ4s0/QW4Ynr925FjTjvRhq7tsLltv4vkxWk=");
  }
}
