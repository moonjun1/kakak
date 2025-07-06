package com.example.demo.domain.auth.controller;

import com.example.demo.domain.auth.service.AuthService;
import com.example.demo.domain.user.entity.User;
import com.example.demo.global.jwt.JwtTokenProvider;
import com.example.demo.global.redis.RedisService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final JwtTokenProvider jwtTokenProvider;
    private final RedisService redisService;
    private final AuthService authService;

    // 토큰 갱신 API (쿠키 방식)
    @PostMapping("/refresh")
    public ResponseEntity<Map<String, Object>> refresh(HttpServletRequest request,
                                                       HttpServletResponse response) {
        // 1. 쿠키에서 Refresh Token 추출
        String refreshToken = extractTokenFromCookie(request, "refreshToken");
        String kakaoId = extractKakaoIdFromAccessToken(request);

        if (!StringUtils.hasText(refreshToken) || !StringUtils.hasText(kakaoId)) {
            return ResponseEntity.status(401).body(Map.of("error", "토큰이 없습니다"));
        }

        // 2. Refresh Token 유효성 검증 (Redis에서 확인)
        if (!redisService.validateRefreshToken(kakaoId, refreshToken)) {
            return ResponseEntity.status(401).body(Map.of("error", "유효하지 않은 refresh token"));
        }

        // 3. 새로운 Access Token 생성
        String newAccessToken = jwtTokenProvider.generateAccessToken(kakaoId);

        // 4. 새로운 Refresh Token 생성 (RTR 방식)
        String newRefreshToken = jwtTokenProvider.generateRefreshToken();
        redisService.saveRefreshToken(kakaoId, newRefreshToken);

        // 5. 새 토큰들을 쿠키로 설정
        setTokenCookies(response, newAccessToken, newRefreshToken);

        Map<String, Object> responseData = new HashMap<>();
        responseData.put("message", "토큰 갱신 성공");
        responseData.put("kakaoId", kakaoId);

        log.info("토큰 갱신 성공: kakaoId = {}", kakaoId);
        return ResponseEntity.ok(responseData);
    }

    // 로그아웃 API (쿠키 + Redis 삭제)
    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(HttpServletRequest request,
                                                      HttpServletResponse response,
                                                      Authentication authentication) {

        String kakaoId = null;

        // 1. Authentication에서 kakaoId 추출 시도
        if (authentication != null) {
            kakaoId = authentication.getName();
        } else {
            // 2. 만료된 토큰에서도 kakaoId 추출 시도
            kakaoId = extractKakaoIdFromAccessToken(request);
        }

        // 3. Redis에서 Refresh Token 삭제
        if (StringUtils.hasText(kakaoId)) {
            redisService.deleteRefreshToken(kakaoId);
            log.info("로그아웃 성공: kakaoId = {}", kakaoId);
        }

        // 4. 쿠키 삭제 (만료시간을 0으로 설정)
        clearTokenCookies(response);

        return ResponseEntity.ok(Map.of("message", "로그아웃 성공"));
    }

    // 현재 사용자 정보 조회 API
    @PostMapping("/me")
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

    // 쿠키에서 토큰 추출 헬퍼 메서드
    private String extractTokenFromCookie(HttpServletRequest request, String cookieName) {
        Cookie[] cookies = request.getCookies();

        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookieName.equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }

        return null;
    }

    // Access Token에서 kakaoId 추출 (만료된 토큰도 처리)
    private String extractKakaoIdFromAccessToken(HttpServletRequest request) {
        String accessToken = extractTokenFromCookie(request, "accessToken");

        if (StringUtils.hasText(accessToken)) {
            try {
                return jwtTokenProvider.getKakaoIdFromToken(accessToken);
            } catch (Exception e) {
                log.warn("만료된 토큰에서 kakaoId 추출 실패: {}", e.getMessage());
            }
        }

        return null;
    }

    // 토큰 쿠키 설정 헬퍼 메서드
    private void setTokenCookies(HttpServletResponse response, String accessToken, String refreshToken) {
        // Access Token 쿠키
        Cookie accessTokenCookie = new Cookie("accessToken", accessToken);
        accessTokenCookie.setHttpOnly(true);
        accessTokenCookie.setSecure(false); // 개발환경에서는 false
        accessTokenCookie.setPath("/");
        accessTokenCookie.setMaxAge(30 * 60); // 30분
        response.addCookie(accessTokenCookie);

        // Refresh Token 쿠키
        Cookie refreshTokenCookie = new Cookie("refreshToken", refreshToken);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(false);
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setMaxAge(14 * 24 * 60 * 60); // 2주
        response.addCookie(refreshTokenCookie);
    }

    // 토큰 쿠키 삭제 헬퍼 메서드
    private void clearTokenCookies(HttpServletResponse response) {
        // Access Token 쿠키 삭제
        Cookie accessTokenCookie = new Cookie("accessToken", "");
        accessTokenCookie.setHttpOnly(true);
        accessTokenCookie.setPath("/");
        accessTokenCookie.setMaxAge(0); // 즉시 만료
        response.addCookie(accessTokenCookie);

        // Refresh Token 쿠키 삭제
        Cookie refreshTokenCookie = new Cookie("refreshToken", "");
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setMaxAge(0); // 즉시 만료
        response.addCookie(refreshTokenCookie);
    }
}