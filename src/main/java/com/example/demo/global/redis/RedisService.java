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

    @Value("${jwt.refresh-token-expire-time}")
    private long refreshTokenExpireTime;

    // Refresh Token 저장
    public void saveRefreshToken(String kakaoId, String refreshToken) {
        String key = "refresh_token:" + kakaoId;

        // TTL 설정 (만료시간)
        redisTemplate.opsForValue().set(key, refreshToken, refreshTokenExpireTime, TimeUnit.MILLISECONDS);

        log.info("Refresh Token 저장 완료: kakaoId = {}", kakaoId);
    }

    // Refresh Token 조회
    public String getRefreshToken(String kakaoId) {
        String key = "refresh_token:" + kakaoId;
        Object refreshToken = redisTemplate.opsForValue().get(key);

        return refreshToken != null ? refreshToken.toString() : null;
    }

    // Refresh Token 삭제 (로그아웃 시)
    public void deleteRefreshToken(String kakaoId) {
        String key = "refresh_token:" + kakaoId;
        redisTemplate.delete(key);

        log.info("Refresh Token 삭제 완료: kakaoId = {}", kakaoId);
    }

    // Refresh Token 존재 여부 확인
    public boolean hasRefreshToken(String kakaoId) {
        String key = "refresh_token:" + kakaoId;
        return Boolean.TRUE.equals(redisTemplate.hasKey(key));
    }

    // Refresh Token 유효성 검증
    public boolean validateRefreshToken(String kakaoId, String refreshToken) {
        String storedToken = getRefreshToken(kakaoId);
        return storedToken != null && storedToken.equals(refreshToken);
    }
}