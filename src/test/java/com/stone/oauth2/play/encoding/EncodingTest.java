package com.stone.oauth2.play.encoding;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootTest
public class EncodingTest {

    private static final Logger log = LoggerFactory.getLogger(EncodingTest.class);


    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    public void encodeTest() {
        log.info("@testSecret encoding==>{}", passwordEncoder.encode("testSecret"));
        log.info("@password encoding====>{}", passwordEncoder.encode("new1234@"));
    }
}
