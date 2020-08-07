package com.stone.oauth2.play.auth.controller;

import com.google.gson.Gson;
import com.stone.oauth2.play.auth.domain.OAuthToken;
import lombok.RequiredArgsConstructor;
import org.apache.commons.codec.binary.Base64;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

/**
 * Client Side Test Controller Code
 */
@RequiredArgsConstructor
@RestController
@RequestMapping("/oauth2")
public class Oauth2Controller {

    private final Gson gson;
    private final RestTemplate restTemplate;

//    @GetMapping(value = "/callback")
//    public OAuthToken callbackSocial(@RequestParam String code) {
//        HttpHeaders headers = getHttpHeader();
//        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
//        params.add("code", code);
//        params.add("grant_type", "authorization_code");
//        params.add("redirect_uri", "http://localhost:8081/oauth2/callback");
//        return getOAuthToken(headers, params);
//    }

//    @GetMapping(value = "/token/refresh")
//    public OAuthToken refreshToken(@RequestParam String refreshToken) {
//        HttpHeaders headers = getHttpHeader();
//        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
//        params.add("refresh_token", refreshToken);
//        params.add("grant_type", "refresh_token");
//        return getOAuthToken(headers, params);
//    }

    private HttpHeaders getHttpHeader() {
        String credentials = "testClientId:testSecret";
        String encodedCredentials = new String(Base64.encodeBase64(credentials.getBytes()));
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.add("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.add("Authorization", "Basic " + encodedCredentials);
        return headers;
    }

    private OAuthToken getOAuthToken(HttpHeaders headers, MultiValueMap<String, String> params) {
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);
        ResponseEntity<String> response = restTemplate.postForEntity("http://localhost:8081/oauth/token", request, String.class);
        if (response.getStatusCode() == HttpStatus.OK) {
            return gson.fromJson(response.getBody(), OAuthToken.class);
        }
        return null;
    }
}
