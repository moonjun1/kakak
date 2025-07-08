package com.example.demo.domain.user.repository;

import com.example.demo.domain.user.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    // user_id(카카오ID)로 사용자 조회
    Optional<User> findByUserId(String userId);

    // user_id(카카오ID)로 사용자 존재 여부 확인
    boolean existsByUserId(String userId);
}