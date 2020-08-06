package com.stone.oauth2.play.repository;

import com.stone.oauth2.play.auth.domain.User;
import com.stone.oauth2.play.auth.repository.UserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Collections;

@SpringBootTest
public class UserRepositoryTest {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    @DisplayName("테스트용 사용자 정보 삽입")
    public void insert_user_info() {
        // given
        userRepository.save(User.builder()
                .uid("stoneberg@gmail.com")
                .password(passwordEncoder.encode("new1234@"))
                .name("stoneberg")
                .roles(Collections.singletonList("ROLE_USER"))
                .build());
    }
}
