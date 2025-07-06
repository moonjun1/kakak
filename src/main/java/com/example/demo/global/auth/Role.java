package com.example.demo.global.auth;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum Role {

    ROLE_USER("USER"),
    ROLE_ADMIN("ADMIN");  // 나중에 필요하면 사용

    private final String role;
}
