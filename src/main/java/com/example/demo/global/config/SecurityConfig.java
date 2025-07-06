package com.example.demo.global.config;

import com.example.demo.global.jwt.JwtAuthenticationFilter;
import com.example.demo.global.oauth.CustomOAuth2UserService;
import com.example.demo.global.oauth.OAuth2LoginSuccessHandler;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler;

    @Bean
    public ObjectMapper objectMapper() {
        return new ObjectMapper();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        return http
                // CSRF 보호 기능 비활성화 (JWT 사용하므로 불필요)
                .csrf(AbstractHttpConfigurer::disable)

                // URL별 접근 권한 설정
                .authorizeHttpRequests(auth -> auth
                        // 정적 리소스는 누구나 접근 가능
                        .requestMatchers("/", "/index.html", "/*.html", "/favicon.ico",
                                "/css/**", "/js/**", "/images/**").permitAll()

                        // 인증 관련 API는 누구나 접근 가능
                        .requestMatchers("/api/auth/**", "/oauth2/**", "/login/**").permitAll()

                        // 사용자 관련 API는 인증 필요
                        .requestMatchers("/api/user/**", "/api/news/**").authenticated()

                        // 나머지 모든 요청은 인증 필요
                        .anyRequest().authenticated()
                )

                // 인증 실패시 예외 처리
                .exceptionHandling(e -> e
                        // 인증되지 않은 사용자가 접근할 때
                        .authenticationEntryPoint((request, response, authException) -> {
                            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
                        })
                        // 권한이 없는 사용자가 접근할 때
                        .accessDeniedHandler((request, response, accessDeniedException) -> {
                            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Forbidden");
                        })
                )

                // 세션 관리 정책 설정
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)  // 세션 사용 안함
                )

                // OAuth2 로그인 설정 (새로 추가)
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/login")  // 로그인 페이지 경로
                        .userInfoEndpoint(userInfo -> userInfo
                                .userService(customOAuth2UserService)  // 커스텀 OAuth2 사용자 서비스
                        )
                        .successHandler(oAuth2LoginSuccessHandler)  // 로그인 성공 핸들러
                )

                // JWT 필터를 Spring Security 필터 체인에 추가
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)

                .build();
    }

    // 비밀번호 암호화 (나중에 필요할 수 있음)
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}