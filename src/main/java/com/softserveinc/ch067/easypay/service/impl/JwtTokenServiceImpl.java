package com.softserveinc.ch067.easypay.service.impl;

import com.softserveinc.ch067.easypay.service.IJwtTokenService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

@PropertySource("classpath:jwt.properties")
@Service
public class JwtTokenServiceImpl implements IJwtTokenService {

    @Value("${secret}")
    private String secret;
    @Value("${expirationInMinutes}")
    private Long expirationInMinutes;
    @Override
    public String generateAndGetEmailToken(String email) {
        Claims claims = Jwts.claims().setSubject(email);
        LocalDateTime expiration = LocalDateTime.now().plusMinutes(expirationInMinutes);
        return Jwts.builder()
                .setClaims(claims)
                .signWith(SignatureAlgorithm.HS512, secret)
                .setExpiration(Date.from(expiration.atZone(ZoneId.systemDefault()).toInstant()))
                .compact();
    }

    @Override
    public String parseEmailTokenAndGetEmail(String token) throws JwtException {
        return Jwts.parser()
                .setSigningKey(secret)
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }
}
