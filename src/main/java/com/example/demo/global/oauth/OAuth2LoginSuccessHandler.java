package com.example.demo.global.oauth;

import com.example.demo.domain.auth.service.AuthService;
import com.example.demo.domain.user.entity.Auth;
import com.example.demo.domain.user.entity.User;
import com.example.demo.domain.user.repository.AuthRepository;
import com.example.demo.global.jwt.JwtTokenProvider;
import com.example.demo.global.redis.RedisService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
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

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();

        // 1. 카카오에서 받은 사용자 정보 추출
        String kakaoId = oauth2User.getAttribute("id").toString();
        log.info("카카오 로그인 성공: kakaoId = {}", kakaoId);

        // 2. 사용자 로그인 또는 회원가입 처리
        User user = authService.loginOrRegister(kakaoId);

        // 3. JWT 토큰 생성
        String accessToken = jwtTokenProvider.generateAccessToken(kakaoId);
        String refreshToken = jwtTokenProvider.generateRefreshToken();

        // 4. Refresh Token은 Redis에 저장 (성능 + 자동 만료)
        redisService.saveRefreshToken(kakaoId, refreshToken);

        // 5. Auth 메타데이터는 DB에 저장 (감사 로그)
        Optional<Auth> optionalAuth = authRepository.findByUser(user);
        if (optionalAuth.isPresent()) {
            // 기존 Auth가 있으면 로그인 정보 업데이트
            Auth auth = optionalAuth.get();
            auth.updateLogin();
            authRepository.save(auth);
            log.info("기존 사용자 로그인: userId = {}, 로그인 횟수 = {}", user.getId(), auth.getLoginCount());
        } else {
            // 새 사용자면 Auth 생성
            Auth newAuth = Auth.builder()
                    .user(user)
                    .tokenType("Bearer")
                    .build();
            authRepository.save(newAuth);
            user.setAuth(newAuth);
            log.info("새 사용자 Auth 생성: userId = {}", user.getId());
        }

        // 6. Access Token을 HttpOnly 쿠키로 전달 (XSS 방지)
        Cookie accessTokenCookie = new Cookie("accessToken", accessToken);
        accessTokenCookie.setHttpOnly(true);  // JavaScript 접근 차단
        accessTokenCookie.setSecure(false);   // 개발환경에서는 false (HTTPS에서는 true)
        accessTokenCookie.setPath("/");       // 전체 경로에서 사용
        accessTokenCookie.setMaxAge(30 * 60); // 30분
        response.addCookie(accessTokenCookie);

        // 7. Refresh Token도 HttpOnly 쿠키로 전달
        Cookie refreshTokenCookie = new Cookie("refreshToken", refreshToken);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(false);
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setMaxAge(14 * 24 * 60 * 60); // 2주
        response.addCookie(refreshTokenCookie);

        // 8. 성공 페이지로 리다이렉트 (사용자 ID 포함)
        String redirectUrl = "/main.html?id=" + user.getId();
        response.sendRedirect(redirectUrl);

        log.info("하이브리드 OAuth 로그인 완료: userId = {}", user.getId());
    }
}