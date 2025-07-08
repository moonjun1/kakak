package com.example.demo.domain.kakao.service;

import com.example.demo.global.redis.RedisService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class KakaoTokenService {

    private final RedisService redisService;
    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;

    @Value("${spring.security.oauth2.client.registration.kakao.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.kakao.client-secret}")
    private String clientSecret;

    private static final String KAKAO_TOKEN_URL = "https://kauth.kakao.com/oauth/token";

    // 카카오 Access Token 조회 (만료 시 자동 갱신)
    public String getValidKakaoAccessToken(String kakaoId) {
        // 1. 현재 저장된 Access Token 확인
        String accessToken = redisService.getKakaoAccessToken(kakaoId);

        if (accessToken != null) {
            log.debug("카카오 Access Token 존재: kakaoId = {}", kakaoId);
            return accessToken;
        }

        // 2. Access Token이 없으면 Refresh Token으로 갱신 시도
        String refreshToken = redisService.getKakaoRefreshToken(kakaoId);
        if (refreshToken == null) {
            log.warn("카카오 Refresh Token이 없음: kakaoId = {}", kakaoId);
            return null;
        }

        // 3. 토큰 갱신 시도
        return refreshKakaoAccessToken(kakaoId, refreshToken);
    }

    // 카카오 Access Token 갱신
    public String refreshKakaoAccessToken(String kakaoId, String refreshToken) {
        try {
            log.info("카카오 Access Token 갱신 시도: kakaoId = {}", kakaoId);

            // 1. 카카오 토큰 갱신 API 호출
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
            params.add("grant_type", "refresh_token");
            params.add("client_id", clientId);
            params.add("client_secret", clientSecret);
            params.add("refresh_token", refreshToken);

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

            ResponseEntity<String> response = restTemplate.postForEntity(KAKAO_TOKEN_URL, request, String.class);

            if (response.getStatusCode() == HttpStatus.OK) {
                // 2. 응답 파싱
                JsonNode responseJson = objectMapper.readTree(response.getBody());

                String newAccessToken = responseJson.get("access_token").asText();
                String newRefreshToken = responseJson.has("refresh_token")
                        ? responseJson.get("refresh_token").asText()
                        : refreshToken; // 새 Refresh Token이 없으면 기존 것 유지

                // 3. Redis에 새 토큰 저장
                redisService.saveKakaoAccessToken(kakaoId, newAccessToken);
                if (!newRefreshToken.equals(refreshToken)) {
                    redisService.saveKakaoRefreshToken(kakaoId, newRefreshToken);
                }

                log.info("카카오 Access Token 갱신 성공: kakaoId = {}", kakaoId);
                return newAccessToken;

            } else {
                log.error("카카오 토큰 갱신 실패: kakaoId = {}, status = {}", kakaoId, response.getStatusCode());
                return null;
            }

        } catch (Exception e) {
            log.error("카카오 토큰 갱신 중 오류: kakaoId = {}, error = {}", kakaoId, e.getMessage());
            return null;
        }
    }

    // 카카오 토큰 유효성 확인
    public boolean isKakaoTokenValid(String kakaoId) {
        return redisService.hasKakaoAccessToken(kakaoId) || redisService.hasKakaoRefreshToken(kakaoId);
    }

    // 사용자별 카카오 토큰 상태 조회
    public Map<String, Object> getKakaoTokenStatus(String kakaoId) {
        Map<String, Object> status = new HashMap<>();
        status.put("hasAccessToken", redisService.hasKakaoAccessToken(kakaoId));
        status.put("hasRefreshToken", redisService.hasKakaoRefreshToken(kakaoId));
        status.put("expireDate", redisService.getKakaoTokenExpireDate(kakaoId));
        return status;
    }
}