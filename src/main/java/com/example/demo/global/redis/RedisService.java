package com.example.demo.global.redis;

import java.time.LocalDate;
import java.util.HashSet;
import java.util.Set;
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

    // ============ JWT 토큰 관리 (기존) ============

    // JWT Refresh Token 저장
    public void saveRefreshToken(String kakaoId, String refreshToken) {
        String key = "refresh_token:" + kakaoId;
        redisTemplate.opsForValue().set(key, refreshToken, refreshTokenExpireTime, TimeUnit.MILLISECONDS);
        log.info("JWT Refresh Token 저장 완료: kakaoId = {}", kakaoId);
    }

    // JWT Refresh Token 조회
    public String getRefreshToken(String kakaoId) {
        String key = "refresh_token:" + kakaoId;
        Object refreshToken = redisTemplate.opsForValue().get(key);
        return refreshToken != null ? refreshToken.toString() : null;
    }

    // JWT Refresh Token 삭제
    public void deleteRefreshToken(String kakaoId) {
        String key = "refresh_token:" + kakaoId;
        redisTemplate.delete(key);
        log.info("JWT Refresh Token 삭제 완료: kakaoId = {}", kakaoId);
    }

    // JWT Refresh Token 유효성 검증
    public boolean validateRefreshToken(String kakaoId, String refreshToken) {
        String storedToken = getRefreshToken(kakaoId);
        return storedToken != null && storedToken.equals(refreshToken);
    }

    // ============ 카카오 OAuth 토큰 관리 (신규) ============

    // 카카오 OAuth Access Token 저장 (6시간)
    public void saveKakaoAccessToken(String kakaoId, String accessToken) {
        String key = "kakao_access:" + kakaoId;
        redisTemplate.opsForValue().set(key, accessToken, 6, TimeUnit.HOURS);
        log.info("카카오 Access Token 저장 완료: kakaoId = {}", kakaoId);
    }

    // 카카오 OAuth Refresh Token 저장 (2개월)
    public void saveKakaoRefreshToken(String kakaoId, String refreshToken) {
        String key = "kakao_refresh:" + kakaoId;
        redisTemplate.opsForValue().set(key, refreshToken, 60, TimeUnit.DAYS);

        // 만료일 추적용 데이터 저장 (알림용)
        String expireDateKey = "kakao_expire_date:" + kakaoId;
        LocalDate expireDate = LocalDate.now().plusDays(60);
        redisTemplate.opsForValue().set(expireDateKey, expireDate.toString(), 60, TimeUnit.DAYS);

        log.info("카카오 Refresh Token 저장 완료: kakaoId = {}, 만료일 = {}", kakaoId, expireDate);
    }

    // 카카오 OAuth 토큰 한번에 저장
    public void saveKakaoTokens(String kakaoId, String accessToken, String refreshToken) {
        saveKakaoAccessToken(kakaoId, accessToken);
        if (refreshToken != null) {
            saveKakaoRefreshToken(kakaoId, refreshToken);
        }
    }

    // 카카오 Access Token 조회
    public String getKakaoAccessToken(String kakaoId) {
        String key = "kakao_access:" + kakaoId;
        Object token = redisTemplate.opsForValue().get(key);
        return token != null ? token.toString() : null;
    }

    // 카카오 Refresh Token 조회
    public String getKakaoRefreshToken(String kakaoId) {
        String key = "kakao_refresh:" + kakaoId;
        Object token = redisTemplate.opsForValue().get(key);
        return token != null ? token.toString() : null;
    }

    // 카카오 토큰 만료일 조회
    public LocalDate getKakaoTokenExpireDate(String kakaoId) {
        String key = "kakao_expire_date:" + kakaoId;
        Object expireDate = redisTemplate.opsForValue().get(key);
        if (expireDate != null) {
            return LocalDate.parse(expireDate.toString());
        }
        return null;
    }

    // 카카오 토큰 삭제 (로그아웃 시)
    public void deleteKakaoTokens(String kakaoId) {
        redisTemplate.delete("kakao_access:" + kakaoId);
        redisTemplate.delete("kakao_refresh:" + kakaoId);
        redisTemplate.delete("kakao_expire_date:" + kakaoId);
        log.info("카카오 OAuth 토큰 삭제 완료: kakaoId = {}", kakaoId);
    }

    // 카카오 Access Token 존재 여부 확인
    public boolean hasKakaoAccessToken(String kakaoId) {
        String key = "kakao_access:" + kakaoId;
        return Boolean.TRUE.equals(redisTemplate.hasKey(key));
    }

    // 카카오 Refresh Token 존재 여부 확인
    public boolean hasKakaoRefreshToken(String kakaoId) {
        String key = "kakao_refresh:" + kakaoId;
        return Boolean.TRUE.equals(redisTemplate.hasKey(key));
    }

    // ============ 토큰 만료 알림 관련 ============

    // 만료 임박한 토큰 사용자 목록 조회
    public Set<String> getTokensExpiringTomorrow() {
        LocalDate tomorrow = LocalDate.now().plusDays(1);
        Set<String> keys = redisTemplate.keys("kakao_expire_date:*");
        Set<String> expiringUsers = new HashSet<>();

        if (keys != null) {
            for (String key : keys) {
                Object expireDate = redisTemplate.opsForValue().get(key);
                if (expireDate != null && tomorrow.equals(LocalDate.parse(expireDate.toString()))) {
                    String kakaoId = key.replace("kakao_expire_date:", "");
                    expiringUsers.add(kakaoId);
                }
            }
        }

        return expiringUsers;
    }
}