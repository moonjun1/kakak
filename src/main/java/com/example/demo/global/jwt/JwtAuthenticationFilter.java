package com.example.demo.global.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        try {
            // 1. Authorization 헤더에서 JWT 토큰 추출
            String accessToken = extractTokenFromRequest(request);

            // 2. 토큰이 있고 유효한지 확인
            if (accessToken != null && jwtTokenProvider.validateToken(accessToken)) {

                // 3. 토큰에서 kakao_id 추출
                String kakaoId = jwtTokenProvider.getKakaoIdFromToken(accessToken);

                // 4. 간단한 인증 객체 생성 (DB 조회 없음)
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(
                                kakaoId,  // principal: 사용자 식별자
                                null,     // credentials: 비밀번호 (불필요)
                                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"))  // 권한
                        );

                // 5. 요청 세부정보 설정
                authentication.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );

                // 6. SecurityContext에 인증 정보 저장
                SecurityContextHolder.getContext().setAuthentication(authentication);

                log.debug("JWT 인증 성공: kakaoId = {}", kakaoId);
            }

        } catch (Exception e) {
            log.error("JWT 인증 중 오류 발생: {}", e.getMessage());
            SecurityContextHolder.clearContext();
        }

        // 7. 다음 필터로 요청 전달
        filterChain.doFilter(request, response);
    }

    // Authorization 헤더에서 JWT 토큰 추출
    private String extractTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");

        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7); // "Bearer " 제거
        }

        return null;
    }

    // 특정 경로는 필터 적용 제외
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();

        return path.startsWith("/css/")
                || path.startsWith("/js/")
                || path.startsWith("/images/")
                || path.equals("/")
                || path.equals("/index.html")
                || path.startsWith("/oauth2/")    // OAuth2 관련 경로 제외
                || path.startsWith("/login/");    // 로그인 페이지 제외
    }
}