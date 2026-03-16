package com.pragna.profile;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Service
public class JwtService {

    private final SecretKey key;
    private final long accessTokenExpiryMs;
    private final long refreshTokenExpiryMs;

    public JwtService(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.access-token-expiry-ms}") long accessTokenExpiryMs,
            @Value("${jwt.refresh-token-expiry-ms}") long refreshTokenExpiryMs) {

        // Key must be at least 256 bits (32 chars) for HS256
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessTokenExpiryMs  = accessTokenExpiryMs;
        this.refreshTokenExpiryMs = refreshTokenExpiryMs;
    }

    /**
     * Issue a short-lived ACCESS token (15 min).
     * Contains full user profile claims.
     * Sent to client in response body — stored in memory only (never localStorage).
     */
    public String issueAccessToken(String username, String role,
                                   String provider, String loginMethod,
                                   String email, String displayName, String avatar) {
        return Jwts.builder()
                .subject(username)
                .claim("type",        "access")
                .claim("role",        role)
                .claim("provider",    provider)
                .claim("loginMethod", loginMethod)
                .claim("email",       email)
                .claim("displayName", displayName)
                .claim("avatar",      avatar)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + accessTokenExpiryMs))
                .signWith(key)
                .compact();
    }

    /**
     * Issue a long-lived REFRESH token (7 days).
     * Contains minimal claims — only subject and type.
     * Sent to client as HttpOnly, Secure, SameSite=Strict cookie.
     * JS cannot read it — fully protected from XSS.
     */
    public String issueRefreshToken(String username) {
        return Jwts.builder()
                .subject(username)
                .claim("type", "refresh")
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + refreshTokenExpiryMs))
                .signWith(key)
                .compact();
    }

    public Claims validateAndGetClaims(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public boolean isValid(String token) {
        try {
            validateAndGetClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public boolean isAccessToken(String token) {
        try {
            Claims c = validateAndGetClaims(token);
            return "access".equals(c.get("type", String.class));
        } catch (Exception e) {
            return false;
        }
    }

    public boolean isRefreshToken(String token) {
        try {
            Claims c = validateAndGetClaims(token);
            return "refresh".equals(c.get("type", String.class));
        } catch (Exception e) {
            return false;
        }
    }

    public long getRefreshTokenExpiryMs() {
        return refreshTokenExpiryMs;
    }
}
