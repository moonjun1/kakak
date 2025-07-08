package com.example.demo.global.auth;

import com.example.demo.domain.user.entity.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;

@RequiredArgsConstructor
public class CustomUserDetails implements UserDetails {

    private final User user;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.singleton(
                new SimpleGrantedAuthority("ROLE_USER")  // 간단하게 고정값 사용
        );
    }

    // User 엔티티의 ID 반환 (PK)
    public Long getId() {
        return user.getId();
    }

    // 카카오 ID 반환 (사용자 식별자)
    public String getKakaoId() {
        return user.getKakaoId();  // user.getUserId()와 동일
    }

    // 비밀번호 (카카오 로그인이므로 null)
    @Override
    public String getPassword() {
        return null;
    }

    // 사용자명 (kakao_id 사용)
    @Override
    public String getUsername() {
        return user.getKakaoId();
    }

    // 계정 만료 여부 (만료되지 않음)
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    // 계정 잠금 여부 (잠기지 않음)
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    // 자격증명 만료 여부 (만료되지 않음)
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    // 계정 활성화 여부
    @Override
    public boolean isEnabled() {
        return "ACTIVE".equals(user.getStatus());
    }
}