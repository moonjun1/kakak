package com.example.demo.global.auth;

import com.example.demo.domain.user.entity.User;
import com.example.demo.domain.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    // Spring Security가 로그인 시 호출하는 메서드 (username = kakao_id)
    @Override
    public UserDetails loadUserByUsername(String kakaoId) throws UsernameNotFoundException {
        User user = userRepository.findByUserId(kakaoId)  // 변경: findByKakaoId → findByUserId
                .orElseThrow(() -> new UsernameNotFoundException("해당 사용자가 존재하지 않습니다: " + kakaoId));

        return new CustomUserDetails(user);
    }

    // JWT 필터에서 사용할 메서드 (PK로 조회)
    public UserDetails loadUserById(Long id) throws UsernameNotFoundException {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new UsernameNotFoundException("해당 사용자가 존재하지 않습니다: " + id));

        return new CustomUserDetails(user);
    }

    // 카카오 ID로 사용자 조회
    public UserDetails loadUserByKakaoId(String kakaoId) throws UsernameNotFoundException {
        return loadUserByUsername(kakaoId);  // 위 메서드 재사용
    }

    // 사용자 존재 여부 확인
    public boolean existsByKakaoId(String kakaoId) {
        return userRepository.existsByUserId(kakaoId);  // 변경: existsByKakaoId → existsByUserId
    }
}