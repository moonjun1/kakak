package com.example.demo.global.jwt;

import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class JwtTokenProvider {

    private final SecretKey secretKey;

    @Value("${jwt.access-token-expire-time}")
    private long accessTokenExpireTime;

    @Value("${jwt.refresh-token-expire-time}")
    private long refreshTokenExpireTime;

    // Access Token 생성 (메서드명 변경)
    public String generateAccessToken(String kakaoId) {
        Date expiryDate = new Date(new Date().getTime() + accessTokenExpireTime);

        Claims claims = Jwts.claims();
        claims.put("kakao_id", kakaoId);  // "kakaoId" → "kakao_id"로 통일

        return Jwts.builder()
                .setSubject(kakaoId)
                .setClaims(claims)
                .setIssuedAt(new Date())
                .setExpiration(expiryDate)
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();
    }

    // Refresh Token 생성 (새로 추가)
    public String generateRefreshToken() {
        Date expiryDate = new Date(new Date().getTime() + refreshTokenExpireTime);

        return Jwts.builder()
                .setSubject(UUID.randomUUID().toString())
                .setIssuedAt(new Date())
                .setExpiration(expiryDate)
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();
    }

    public String getKakaoIdFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .get("kakao_id", String.class);  // "kakaoId" → "kakao_id"로 통일
    }

    // 토큰 유효성 검증
    public Boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (MalformedJwtException e) {
            return false;
        } catch (ExpiredJwtException e) {
            return false;
        } catch (UnsupportedJwtException e) {
            return false;
        } catch (IllegalArgumentException e) {
            return false;
        } catch (JwtException e) {
            return false;
        }
    }
}