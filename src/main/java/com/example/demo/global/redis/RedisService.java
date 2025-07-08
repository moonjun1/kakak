package com.example.demo.global.redis;

import java.util.concurrent.TimeUnit;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class RedisService {

    private final RedisTemplate<String, Object> redisTemplate;

    @Value("${jwt.access-token-expire-time}")
    private long accessTokenExpireTime;

    @Value("${jwt.refresh-token-expire-time}")
    private long refreshTokenExpireTime;

    // ============ 우리 서비스 JWT 토큰 관리 ============

    // 우리 서비스 Access Token 저장 (30분)
    public void saveAccessToken(String kakaoId, String accessToken) {
        String key = "access_token:" + kakaoId;
        redisTemplate.opsForValue().set(key, accessToken, accessTokenExpireTime, TimeUnit.MILLISECONDS);
        log.info("우리 Access Token 저장 완료: kakaoId = {}", kakaoId);
    }

    // 우리 서비스 Refresh Token 저장 (14일)
    public void saveRefreshToken(String kakaoId, String refreshToken) {
        String key = "refresh_token:" + kakaoId;
        redisTemplate.opsForValue().set(key, refreshToken, refreshTokenExpireTime, TimeUnit.MILLISECONDS);
        log.info("우리 Refresh Token 저장 완료: kakaoId = {}", kakaoId);
    }

    // 우리 서비스 Access Token 조회
    public String getAccessToken(String kakaoId) {
        String key = "access_token:" + kakaoId;
        Object token = redisTemplate.opsForValue().get(key);
        return token != null ? token.toString() : null;
    }

    // 우리 서비스 Refresh Token 조회
    public String getRefreshToken(String kakaoId) {
        String key = "refresh_token:" + kakaoId;
        Object token = redisTemplate.opsForValue().get(key);
        return token != null ? token.toString() : null;
    }

    // 우리 서비스 토큰 삭제 (로그아웃 시)
    public void deleteTokens(String kakaoId) {
        redisTemplate.delete("access_token:" + kakaoId);
        redisTemplate.delete("refresh_token:" + kakaoId);
        log.info("우리 서비스 토큰 삭제 완료: kakaoId = {}", kakaoId);
    }

    // Refresh Token 유효성 검증
    public boolean validateRefreshToken(String kakaoId, String refreshToken) {
        String storedToken = getRefreshToken(kakaoId);
        return storedToken != null && storedToken.equals(refreshToken);
    }
}