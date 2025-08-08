package com.yia0507.boot_edu_jwt_250806.util;

import io.jsonwebtoken.JwtException;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
@Log4j2
public class JWTUtil {
    @Value("${com.yia0507.jwt.secret}")
    private String key;

    public String generateToken(Map<String,Object> valueMap, int days) {
        /* JWT 문자열 생성 */
        log.info("generateKey: {}", key);

        //헤더 부분
        Map<String, Object> headers = new HashMap<>();
        headers.put("typ", "JWT");
        headers.put("alg", "HS256");

        //payload 부분 설정
        Map<String, Object> payload = new HashMap<>();
        payload.putAll(valueMap);

        //테스트 시에는 짧은 유효기간
        int time = (60*24) * days; //테스트는 분단위로 나중에 60*24 (일)단위 변경
        String jwtStr = Jwts.builder()
                .setHeader(headers)
                .setClaims(payload)
                .setIssuedAt(Date.from(ZonedDateTime.now().toInstant())) //발행 시간
                .setExpiration(Date.from(ZonedDateTime.now().plusMinutes(time).toInstant())) //만료시간
                .signWith(SignatureAlgorithm.HS256, key.getBytes())
                .compact();
        return jwtStr;
    }

    public Map<String,Object> validateToken(String token) throws JwtException {
        /*토큰을 검증*/
        Map<String,Object> claim = null;
        byte[] bytes = key.getBytes();
        SecretKey key = Keys.hmacShaKeyFor(bytes);

        claim = Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)//파싱 및 검증, 실패시 에러
                .getPayload();
        return claim;
    }
}
