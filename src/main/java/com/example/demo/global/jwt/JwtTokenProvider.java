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

    // Access Token 생성
    public String generateAccessToken(String kakaoId) {
        Date expiryDate = new Date(new Date().getTime() + accessTokenExpireTime);

        Claims claims = Jwts.claims();
        claims.put("kakao_id", kakaoId);
        claims.put("token_type", "access");

        return Jwts.builder()
                .setSubject(kakaoId)
                .setClaims(claims)
                .setIssuedAt(new Date())
                .setExpiration(expiryDate)
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();
    }

    // Refresh Token 생성 (kakaoId 포함하도록 수정)
    public String generateRefreshToken() {
        Date expiryDate = new Date(new Date().getTime() + refreshTokenExpireTime);

        Claims claims = Jwts.claims();
        claims.put("token_type", "refresh");

        return Jwts.builder()
                .setSubject(UUID.randomUUID().toString())
                .setClaims(claims)
                .setIssuedAt(new Date())
                .setExpiration(expiryDate)
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();
    }

    // Refresh Token 생성 (kakaoId 포함 버전 - 추천)
    public String generateRefreshTokenWithKakaoId(String kakaoId) {
        Date expiryDate = new Date(new Date().getTime() + refreshTokenExpireTime);

        Claims claims = Jwts.claims();
        claims.put("kakao_id", kakaoId);
        claims.put("token_type", "refresh");

        return Jwts.builder()
                .setSubject(kakaoId)
                .setClaims(claims)
                .setIssuedAt(new Date())
                .setExpiration(expiryDate)
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();
    }

    // 토큰에서 kakaoId 추출
    public String getKakaoIdFromToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();

        return claims.get("kakao_id", String.class);
    }

    // 토큰에서 토큰 타입 확인
    public String getTokenTypeFromToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();

        return claims.get("token_type", String.class);
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

    // 토큰 만료 시간 확인
    public Date getExpirationDateFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getExpiration();
    }

    // 토큰이 만료되었는지 확인
    public Boolean isTokenExpired(String token) {
        Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }
}