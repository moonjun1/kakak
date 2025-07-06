package com.example.demo.domain.auth.service;

import com.example.demo.domain.user.entity.User;
import com.example.demo.domain.user.repository.UserRepository;
import com.example.demo.global.auth.Role;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class AuthService {

    private final UserRepository userRepository;

    // 로그인 또는 회원가입 (카카오 로그인 시 자동 가입)
    public User loginOrRegister(String kakaoId) {
        // 1. 기존 사용자 확인
        return userRepository.findByKakaoId(kakaoId)
                .orElseGet(() -> {
                    // 2. 없으면 자동 회원가입
                    User newUser = User.builder()
                            .kakaoId(kakaoId)
                            .status("ACTIVE")
                            .role(Role.ROLE_USER)
                            .build();

                    User savedUser = userRepository.save(newUser);
                    log.info("새 사용자 가입: kakaoId = {}, userId = {}", kakaoId, savedUser.getId());

                    return savedUser;
                });
    }

    // 카카오 ID로 사용자 조회
    @Transactional(readOnly = true)
    public User findByKakaoId(String kakaoId) {
        return userRepository.findByKakaoId(kakaoId)
                .orElseThrow(() -> new IllegalArgumentException("사용자를 찾을 수 없습니다: " + kakaoId));
    }

    // 사용자 존재 여부 확인
    @Transactional(readOnly = true)
    public boolean existsByKakaoId(String kakaoId) {
        return userRepository.existsByKakaoId(kakaoId);
    }

    // 사용자 상태 변경
    public void updateUserStatus(String kakaoId, String status) {
        User user = findByKakaoId(kakaoId);
        user.updateStatus(status);

        log.info("사용자 상태 변경: kakaoId = {}, status = {}", kakaoId, status);
    }
}