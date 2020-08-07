package com.stone.oauth2.play.encoding;

import org.apache.commons.codec.binary.Base64;
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
    public void passwordEncodeTest() {
        log.info("@testSecret encoding==>{}", passwordEncoder.encode("testSecret"));
        log.info("@password encoding====>{}", passwordEncoder.encode("new1234@"));
    }

    @Test
    public void base64EncodeTest() {
        String credentials = "testClientId:testSecret";
        String encodedCredentials = new String(Base64.encodeBase64(credentials.getBytes()));
        log.info("@encodedCredentials encoding====>{}", encodedCredentials);
    }

}
