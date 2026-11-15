package com.zev.identity_guard.security;

import com.zev.identity_guard.entity.AppUser;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.UUID;

@Service
public class JwtService {

    // 1. Injecting configuration from application.yml
    @Value("${spring.application.security.jwt.secret-key}")
    private String secretKey;

    @Value("${spring.application.security.jwt.access-token-expiration}")
    private long jwtExpiration;

    // 2. The Cryptographic Key Generator
    private SecretKey getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    // 3. Generating the Access Token (The 15-minute VIP Pass)
    public String generateAccessToken(AppUser user) {
        return Jwts.builder()
                .subject(user.getId().toString())
                .claim("role", user.getRole())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + jwtExpiration))
                .signWith(getSignInKey())
                .compact();
    }

    // 4. Generating the Refresh Token (The 7-day Master Key)
    public String generateRefreshToken() {
        return UUID.randomUUID().toString();
    }

    //5. Extract user id from jwt

    public String extractUserId(String token){
        return extractAllClaims(token).getSubject();
    }

    //6. Extract role from jwt

    public String extractRole(String token){
        return extractAllClaims(token).get("role",String.class);
    }

    //7. parse and cryptographically verify the jwt signature and expiration

    private Claims extractAllClaims(String token){
        return Jwts.parser()
                .verifyWith(getSignInKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}