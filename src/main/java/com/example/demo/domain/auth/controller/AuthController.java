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

    // 토큰 갱신 API (완전 수정)
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

            // 2. Refresh Token에서 kakaoId 추출 (✅ 이제 가능)
            String kakaoId = jwtTokenProvider.getKakaoIdFromToken(refreshToken);

            if (kakaoId == null) {
                return ResponseEntity.status(401).body(Map.of("error", "토큰에서 사용자 정보를 찾을 수 없습니다"));
            }

            // 3. Redis에서 저장된 Refresh Token과 비교 검증
            if (!redisService.validateRefreshToken(kakaoId, refreshToken)) {
                return ResponseEntity.status(401).body(Map.of("error", "저장된 토큰과 일치하지 않습니다"));
            }

            // 4. 사용자 존재 여부 확인
            if (!authService.existsByKakaoId(kakaoId)) {
                return ResponseEntity.status(401).body(Map.of("error", "존재하지 않는 사용자입니다"));
            }

            // 5. 새로운 토큰들 생성 (RTR 방식 - Refresh Token Rotation)
            String newAccessToken = jwtTokenProvider.generateAccessToken(kakaoId);
            String newRefreshToken = jwtTokenProvider.generateRefreshTokenWithKakaoId(kakaoId);

            // 6. 기존 Refresh Token 삭제 후 새 토큰 저장
            redisService.deleteRefreshToken(kakaoId);
            redisService.saveRefreshToken(kakaoId, newRefreshToken);

            // 7. 응답 데이터 구성
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("accessToken", newAccessToken);
            responseData.put("refreshToken", newRefreshToken);
            responseData.put("tokenType", "Bearer");
            responseData.put("expiresIn", 1800);
            responseData.put("message", "토큰 갱신 성공");

            log.info("토큰 갱신 성공: kakaoId = {}", kakaoId);
            return ResponseEntity.ok(responseData);

        } catch (Exception e) {
            log.error("토큰 갱신 실패: {}", e.getMessage());
            return ResponseEntity.status(401).body(Map.of("error", "토큰 갱신 실패: " + e.getMessage()));
        }
    }

    // 로그아웃 API
    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(Authentication authentication) {

        if (authentication == null) {
            return ResponseEntity.status(401).body(Map.of("error", "인증되지 않은 사용자"));
        }

        String kakaoId = authentication.getName();

        // Redis에서 Refresh Token 삭제
        redisService.deleteRefreshToken(kakaoId);

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
        response.put("role", user.getRole());
        response.put("createdAt", user.getCreatedAt());

        return ResponseEntity.ok(response);
    }

    // 토큰 검증 API (추가)
    @PostMapping("/validate")
    public ResponseEntity<Map<String, Object>> validateToken(Authentication authentication) {

        if (authentication == null) {
            return ResponseEntity.status(401).body(Map.of("error", "유효하지 않은 토큰"));
        }

        String kakaoId = authentication.getName();
        Map<String, Object> response = new HashMap<>();
        response.put("valid", true);
        response.put("kakaoId", kakaoId);
        response.put("message", "유효한 토큰입니다");

        return ResponseEntity.ok(response);
    }
}