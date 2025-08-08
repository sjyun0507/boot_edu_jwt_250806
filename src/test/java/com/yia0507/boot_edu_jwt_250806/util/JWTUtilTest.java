package com.yia0507.boot_edu_jwt_250806.util;

import lombok.extern.log4j.Log4j2;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Map;


@Log4j2
@SpringBootTest
class JWTUtilTest {
    @Autowired
    private JWTUtil jwtUtil;

    @Test
    public void testGenerateToken() {
        Map<String,Object> claimMap = Map.of("mid", "ABCDE");
        String jwtStr = jwtUtil.generateToken(claimMap,1);
        log.info("jwtstr:{}",jwtStr);
    }

    @Test
    public void testValidateToken() {
        String jwtStr = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJtaWQiOiJBQkNFRCIsImlhdCI6MTc1NDUyNzMwMiwiZXhwIjoxNzU0NTI3MzYyfQ.KIAsKH5_RLTyAhtRhSYlq75-J2JU8oWsdhyncmNycP";
        Map<String,Object> claim = jwtUtil.validateToken(jwtStr);
        log.info("claim:{}",claim);
    }

    @Test
    public void testAll(){
        Map<String,Object> claimMap = Map.of("mid", "ABCDE","email","abc@gmail.com");
        String jwtStr = jwtUtil.generateToken(claimMap,1);

        Map<String,Object> claim = jwtUtil.validateToken(jwtStr);
        log.info("MID:{}",claim.get("mid"));
        log.info("EMAIL:{}",claim.get("email"));
    }
}