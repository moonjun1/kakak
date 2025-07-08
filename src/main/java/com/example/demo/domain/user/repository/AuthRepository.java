package com.example.demo.domain.user.repository;

import com.example.demo.domain.user.entity.Auth;
import com.example.demo.domain.user.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface AuthRepository extends JpaRepository<Auth, Long> {

    // User로 Auth 조회
    Optional<Auth> findByUser(User user);

    // User로 Auth 존재 여부 확인
    boolean existsByUser(User user);

    // User로 Auth 삭제
    void deleteByUser(User user);
}