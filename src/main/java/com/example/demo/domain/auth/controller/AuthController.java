package com.example.demo.domain.auth.controller;

import com.example.demo.domain.auth.service.AuthService;
import com.example.demo.domain.user.entity.User;
import com.example.demo.global.jwt.JwtTokenProvider;
import com.example.demo.global.redis.RedisService;
import java.util.HashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final JwtTokenProvider jwtTokenProvider;
    private final RedisService redisService;
    private final AuthService authService;

    // 토큰 갱신 API
    @PostMapping("/refresh")
    public ResponseEntity<Map<String, Object>> refresh(@RequestBody Map<String, String> request) {

        String refreshToken = request.get("refreshToken");

        if (!StringUtils.hasText(refreshToken)) {
            return ResponseEntity.status(401).body(Map.of("error", "Refresh token이 없습니다"));
        }

        try {
            // 1. Refresh Token 유효성 검증
            if (!jwtTokenProvider.validateToken(refreshToken)) {
                return ResponseEntity.status(401).body(Map.of("error", "유효하지 않은 refresh token"));
            }

            // 2. Refresh Token에서 kakaoId 추출
            String kakaoId = jwtTokenProvider.getKakaoIdFromToken(refreshToken);

            // 3. Redis에서 저장된 Refresh Token과 비교 검증
            if (!redisService.validateRefreshToken(kakaoId, refreshToken)) {
                return ResponseEntity.status(401).body(Map.of("error", "저장된 토큰과 일치하지 않습니다"));
            }

            // 4. 새로운 토큰들 생성
            String newAccessToken = jwtTokenProvider.generateAccessToken(kakaoId);
            String newRefreshToken = jwtTokenProvider.generateRefreshTokenWithKakaoId(kakaoId);

            // 5. Redis에 새 토큰 저장
            redisService.saveAccessToken(kakaoId, newAccessToken);
            redisService.saveRefreshToken(kakaoId, newRefreshToken);

            // 6. 응답
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("accessToken", newAccessToken);
            responseData.put("refreshToken", newRefreshToken);
            responseData.put("tokenType", "Bearer");
            responseData.put("expiresIn", 1800);

            log.info("토큰 갱신 성공: kakaoId = {}", kakaoId);
            return ResponseEntity.ok(responseData);

        } catch (Exception e) {
            log.error("토큰 갱신 실패: {}", e.getMessage());
            return ResponseEntity.status(401).body(Map.of("error", "토큰 갱신 실패"));
        }
    }

    // 로그아웃 API
    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(Authentication authentication) {
        if (authentication == null) {
            return ResponseEntity.status(401).body(Map.of("error", "인증되지 않은 사용자"));
        }

        String kakaoId = authentication.getName();
        redisService.deleteTokens(kakaoId);

        log.info("로그아웃 성공: kakaoId = {}", kakaoId);
        return ResponseEntity.ok(Map.of("message", "로그아웃 성공"));
    }

    // 현재 사용자 정보 조회 API
    @GetMapping("/me")
    public ResponseEntity<Map<String, Object>> getCurrentUser(Authentication authentication) {
        if (authentication == null) {
            return ResponseEntity.status(401).body(Map.of("error", "인증되지 않은 사용자"));
        }

        String kakaoId = authentication.getName();
        User user = authService.findByKakaoId(kakaoId);

        Map<String, Object> response = new HashMap<>();
        response.put("id", user.getId());
        response.put("kakaoId", user.getKakaoId());
        response.put("status", user.getStatus());
        response.put("createdAt", user.getCreatedAt());

        return ResponseEntity.ok(response);
    }
}