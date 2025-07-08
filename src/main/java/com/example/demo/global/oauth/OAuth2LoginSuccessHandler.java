package com.example.demo.global.oauth;

import com.example.demo.domain.auth.service.AuthService;
import com.example.demo.domain.user.entity.Auth;
import com.example.demo.domain.user.entity.User;
import com.example.demo.domain.user.repository.AuthRepository;
import com.example.demo.global.jwt.JwtTokenProvider;
import com.example.demo.global.redis.RedisService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtTokenProvider jwtTokenProvider;
    private final RedisService redisService;
    private final AuthService authService;
    private final AuthRepository authRepository;
    private final ObjectMapper objectMapper;
    private final OAuth2AuthorizedClientService authorizedClientService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
        String kakaoId = oauth2User.getAttribute("id").toString();
        log.info("카카오 로그인 성공: kakaoId = {}", kakaoId);

        // 1. 카카오 리프레시 토큰 추출
        String kakaoRefreshToken = null;
        try {
            OAuth2AuthorizedClient authorizedClient = authorizedClientService
                    .loadAuthorizedClient("kakao", authentication.getName());
            if (authorizedClient != null) {
                OAuth2RefreshToken refreshToken = authorizedClient.getRefreshToken();
                kakaoRefreshToken = refreshToken != null ? refreshToken.getTokenValue() : null;
                log.info("카카오 리프레시 토큰 추출 성공: kakaoId = {}", kakaoId);
            }
        } catch (Exception e) {
            log.error("카카오 토큰 추출 실패: {}", e.getMessage());
        }

        // 2. User 테이블에 카카오ID 저장
        User user = authService.loginOrRegister(kakaoId);

        // 3. Auth 테이블에 카카오 리프레시 토큰 저장
        Optional<Auth> optionalAuth = authRepository.findByUser(user);
        if (optionalAuth.isPresent()) {
            Auth auth = optionalAuth.get();
            if (kakaoRefreshToken != null) {
                auth.updateKakaoRefreshToken(kakaoRefreshToken);
                authRepository.save(auth);
                log.info("기존 사용자 - 카카오 토큰 DB 저장: userId = {}", user.getId());
            }
        } else {
            Auth newAuth = Auth.builder()
                    .user(user)
                    .refreshKey(kakaoRefreshToken)
                    .build();
            authRepository.save(newAuth);
            user.setAuth(newAuth);
            log.info("새 사용자 - 카카오 토큰 DB 저장: userId = {}", user.getId());
        }

        // 4. 우리 서비스 JWT 토큰 생성
        String ourAccessToken = jwtTokenProvider.generateAccessToken(kakaoId);
        String ourRefreshToken = jwtTokenProvider.generateRefreshTokenWithKakaoId(kakaoId);

        // 5. Redis에 우리 서비스 JWT 토큰 저장
        redisService.saveAccessToken(kakaoId, ourAccessToken);
        redisService.saveRefreshToken(kakaoId, ourRefreshToken);

        // 6. JSON 응답으로 우리 서비스 토큰 반환
        Map<String, Object> tokenResponse = new HashMap<>();
        tokenResponse.put("accessToken", ourAccessToken);
        tokenResponse.put("refreshToken", ourRefreshToken);
        tokenResponse.put("tokenType", "Bearer");
        tokenResponse.put("expiresIn", 1800);
        tokenResponse.put("user", Map.of(
                "id", user.getId(),
                "kakaoId", user.getKakaoId(),
                "status", user.getStatus()
        ));

        // 7. JSON 응답 설정
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write(objectMapper.writeValueAsString(tokenResponse));

        log.info("토큰 저장 완료 - DB(카카오): {}, Redis(우리JWT): 저장됨", kakaoId);
    }
}