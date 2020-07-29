package com.crypto.symmetricencryption;

import java.security.Key;
import java.util.Base64;
import java.util.Date;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.stereotype.Service;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class JJWTService {

  public String createJwt(String secretKeyString, String metadata) {

    SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;

    long expirationTimeLimit = 20000;
    Date expirationTime = new Date(System.currentTimeMillis() + expirationTimeLimit);

    byte[] decodedKey = Base64.getDecoder().decode(secretKeyString);
    Key signingKey = new SecretKeySpec(decodedKey, signatureAlgorithm.getJcaName());

    Claims claims = Jwts.claims();
    claims.put("data", metadata);

    JwtBuilder jwtBuilder = Jwts.builder().addClaims(claims).setExpiration(expirationTime)
        .signWith(signatureAlgorithm, signingKey);

    String token = jwtBuilder.compact();

    log.info("Token has been generated using JJWT: {}", token);

    return token;
  }

  public String decodeJwtToken(String secretKeyString, String token) {

    SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;

    byte[] decodedKey = Base64.getDecoder().decode(secretKeyString);
    Key signingKey = new SecretKeySpec(decodedKey, signatureAlgorithm.getJcaName());

    Claims claims = Jwts.parser().setSigningKey(signingKey).parseClaimsJws(token).getBody();

    String data = claims.get("data").toString();

    log.info("Data after token has been decoded using JJWT: {}", data);

    return data;
  }
}
