package org.sso.sso.utils;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.sso.sso.model.User;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtTokenUtil {

    @Value("${jwt.secret}")
    private String secretKey;

    @Getter
    @Value("${jwt.access.token.expiration}")
    private long accessTokenExpiration;

    @Getter
    @Value("${jwt.refresh.token.expiration}")
    private long refreshTokenExpiration;
    private static final Logger LOGGER = LoggerFactory.getLogger(JwtRequestFilter.class);

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(secretKey.getBytes());
    }
    public String getSubjectFromToken(String token) {
        Claims claims = validateToken(token);
        return claims.getSubject();
    }

    public String getSessionIdFromToken(String token) {
        Claims claims = validateToken(token);
        return claims.get("sessionId", String.class);
    }

    public Long getUserIdFromToken(String token) {
        Claims claims = validateToken(token);
        Object userIdObj = claims.get("userId");
        if (userIdObj instanceof Integer) {
            return ((Integer) userIdObj).longValue();
        }
        return (Long) userIdObj;
    }
    public boolean isTokenExpired(String token) {
        try {
            Claims claims = validateToken(token);
            return claims.getExpiration().before(new Date());
        } catch (ExpiredJwtException e) {
            return true;
        }
    }

    public String generateAccessToken(String subject, Long userId, String roles, String status, String sessionId) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + accessTokenExpiration);

        return Jwts.builder()
                .setSubject(subject)
                .claim("roles", roles)
                .claim("id", userId)
                .claim("status", status)
                .claim("sessionId", sessionId)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(getSigningKey(), SignatureAlgorithm.HS512)
                .compact();
    }

    public String generateRefreshToken(String subject, Long userId, String sessionId) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + refreshTokenExpiration);

        return Jwts.builder()
                .setSubject(subject)
                .claim("userId", userId)
                .claim("sessionId", sessionId)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(getSigningKey(), SignatureAlgorithm.HS512)
                .compact();
    }
    public Claims validateToken(String token) {
        try {
            return Jwts.parser()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException e) {
            throw e;
        } catch (JwtException | IllegalArgumentException e) {
            throw new RuntimeException("Invalid JWT token", e);
        }
    }
}
