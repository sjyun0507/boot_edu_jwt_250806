package com.yia0507.boot_edu_jwt_250806.security.handler;

import com.google.gson.Gson;
import com.yia0507.boot_edu_jwt_250806.util.JWTUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import java.io.IOException;
import java.util.Map;

@Log4j2
@RequiredArgsConstructor
public class APILoginSuccessHandler implements AuthenticationSuccessHandler {
    private final JWTUtil jwtUtil;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        //로그인에 성공했을 때 호출되는 메서드
        log.info("login Success Handler");

        //반환되는 타입 지정
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        log.info(authentication);
        log.info(authentication.getName()); //사용자 id(username)

        //JWT 토큰에 담을 클레임(claim)을 설정. 여기서는 로그인한 사용자의 id을 "mid"라는 키로 담음.
        Map<String, Object> claim = Map.of("mid",authentication.getName());

        //Access Token 유효기간 1일
        String accessToken = jwtUtil.generateToken(claim,1);

        //Refresh Token 유효기간 30일
        String refreshToken = jwtUtil.generateToken(claim,30);

        //Java 객체를 JSON 문자열로 변환하기 위한 라이브러리
        Gson gson = new Gson();

        //응답에 포함할 데이터를 담은 Map 생성. Access Token 과 Refresh Token 을 포함
        Map<String,Object> keyMap = Map.of("access_token",accessToken,"refresh_token",refreshToken);

        String jsonStr = gson.toJson(keyMap);

        //JSON 응답을 클라이언트에게 전송
        response.getWriter().println(jsonStr);
    }
}
