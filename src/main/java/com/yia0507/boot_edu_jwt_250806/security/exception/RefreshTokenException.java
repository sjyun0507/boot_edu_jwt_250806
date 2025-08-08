package com.yia0507.boot_edu_jwt_250806.security.exception;

import com.google.gson.Gson;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.ErrorResponse;

import java.io.IOException;
import java.util.Date;
import java.util.Map;

public class RefreshTokenException extends RuntimeException{
    /*
    JWT RefreshToken 관련 예외를 처리하는 커스텀 예외 클래스
    */
    private ErrorCase errorCase;

    public enum ErrorCase {
        /*
        NO_ACCESS : 액세스 토큰이 없음
        BAD_ACCESS : 액세스 토큰이 유효하지 않음
        NO_REFRESH: 리프레시 토큰이 없음
        OLD_REFRESH: 리프레시 토큰이 만료됨
        BAD_REFRESH: 리프레시 토큰이 유효하지 않음
         */
        NO_ACCESS, BAD_ACCESS, NO_REFRESH, OLD_REFRESH, BAD_REFRESH
    }

    public RefreshTokenException(ErrorCase errorCase) {
        super(errorCase.name());
        this.errorCase = errorCase;
    }

    public void sendResponseError(HttpServletResponse response) {
        /* 예외 응답 메서드 */
        //HTTP 응답 상태 코드를 401(Unauthorized)로 설정
        response.setStatus(HttpStatus.UNAUTHORIZED.value());

        response.setContentType(MediaType.APPLICATION_JSON_VALUE); //JSON 응답으로 설정

        Gson gson = new Gson();

        String responseStr = gson.toJson(Map.of("msg", errorCase.name(),"time", new Date()));

        try {
            response.getWriter().println(responseStr);

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
