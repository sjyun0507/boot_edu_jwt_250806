package com.yia0507.boot_edu_jwt_250806.security.exception;

import com.google.gson.Gson;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;

import java.io.IOException;
import java.util.Date;
import java.util.Map;

public class AccessTokenException extends RuntimeException {
    /*
    JWT 처리 중 발생할 수 있는 에러를 다루기 위한 커스텀 예외 클래스
     */

    TOKEN_ERROR token_error;

    // 이 열거형은 토큰 처리 중 발생할 수 있는 다양한 에러를 정의.
    public enum TOKEN_ERROR {
        // 각 에러는 HTTP 상태 코드와 메시지를 포함.
        UNACCEPT(401, "Token is null or too short"), // 토큰이 비어 있거나 너무 짧음
        BADTYPE(401, "Token type Bearer"), // 토큰 타입이 Bearer가 아님
        MALFORM(403, "Malformed Token"), // 토큰 형식 자체가 잘못됨
        BADSIGN(403, "BadSignatured Token"), // 서명이 위조됨
        EXPIRED(403, "Expired Token"); // 토큰이 만료됨

        private int status;
        private String msg;

        TOKEN_ERROR(int status, String msg) {
            this.status = status;
            this.msg = msg;
        }

        public int getStatus() {
            return this.status;
        }

        public String getMsg() {
            return this.msg;
        }
    }

    public AccessTokenException(TOKEN_ERROR error) {
        super(error.name()); // // 부모 클래스에 예외명 전달
        this.token_error = error;
    }

    public void sendResponseError(HttpServletResponse response) {
        /* 예외 응답 메서드 */
        response.setStatus(token_error.getStatus()); // HTTP 상태 코드 설정
        response.setContentType(MediaType.APPLICATION_JSON_VALUE); // // JSON 응답으로 설정

        Gson gson = new Gson();

        String responseStr = gson.toJson(Map.of("msg", token_error.getMsg(), "time", new Date()));

        try {
            response.getWriter().println(responseStr);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
