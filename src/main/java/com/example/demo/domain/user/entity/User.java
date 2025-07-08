package com.example.demo.domain.user.entity;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import java.time.LocalDateTime;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

@Entity
@Table(name = "user")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", nullable = false, unique = true)
    private String userId;  // 카카오ID

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    // Auth와 1:1 관계
    @OneToOne(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private Auth auth;

    @Builder
    public User(String userId) {
        this.userId = userId;
    }

    // 기존 코드 호환성을 위한 메서드들
    public String getKakaoId() {
        return this.userId;
    }

    public String getStatus() {
        return "ACTIVE";
    }

    public String getRole() {
        return "ROLE_USER";
    }

    // Auth 설정 메서드
    public void setAuth(Auth auth) {
        this.auth = auth;
    }
}