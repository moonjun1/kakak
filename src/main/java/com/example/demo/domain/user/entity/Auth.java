package com.example.demo.domain.user.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "auth")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Auth {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_key", nullable = false)
    private User user;

    @Column(name = "refresh_key", length = 255)
    private String refreshKey;  // 카카오 리프레시 토큰 저장

    @Builder
    public Auth(User user, String refreshKey) {
        this.user = user;
        this.refreshKey = refreshKey;
    }

    // 카카오 리프레시 토큰 업데이트
    public void updateKakaoRefreshToken(String kakaoRefreshToken) {
        this.refreshKey = kakaoRefreshToken;
    }

    // 카카오 리프레시 토큰 조회
    public String getKakaoRefreshToken() {
        return this.refreshKey;
    }

    // 토큰 존재 여부 확인
    public boolean hasKakaoRefreshToken() {
        return this.refreshKey != null && !this.refreshKey.isEmpty();
    }
}