package com.yia0507.boot_edu_jwt_250806.security.filter;

import com.google.gson.Gson;
import com.yia0507.boot_edu_jwt_250806.security.exception.RefreshTokenException;
import com.yia0507.boot_edu_jwt_250806.util.JWTUtil;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.Map;

@Log4j2
@RequiredArgsConstructor
public class RefreshTokenFilter extends OncePerRequestFilter {
    private final String refreshPath;
    private final JWTUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        /*
        필터의 핵심 로직을 작성하는 메서드
        이 메서드는 HTTP 요청마다 실행되며, 내부에서 조건에 따라 필터 동작 여부를 제어할 수 있음
         */
        String path = request.getRequestURI(); //클라이언트가 요청한 URI

        // 요청 경로가 refreshPath 와 일치하지 않으면 필터를 건너뜀
        // api/token/refresh 외의 경로는 Refresh Token 검사에서 제외
        if (!path.equals(refreshPath)) {
            log.info("skip refresh token filter....");
            filterChain.doFilter(request, response);
            return;
        }
        //요청 경로가 refreshPath 일 경우, 로그 출력
        log.info("Refresh token filter...run.....1");

        //추가되는 코드
        //전송된 JSON 에서 accessToken 과 refreshToken 을 얻어옴.
        Map<String, String> tokens = parseRequestJSON(request);

        String access_token = tokens.get("access_token");
        String refresh_token = tokens.get("refresh_token");

        log.info("access_token:{}",access_token);
        log.info("refresh_token:{}",refresh_token);

        // accessToken 의 검증
        try{
            checkAccessToken(access_token);
        } catch (RefreshTokenException refreshTokenException) {
            refreshTokenException.sendResponseError(response);
            return; //더 이상 실행할 필요 없음
        }
        // Refresh Token 검증

    }
    private Map<String, String> parseRequestJSON(HttpServletRequest request) {
        //JSON 데이터를 분석해서 accessToken, refreshToken 전달 값을 Map 으로 처리
        try (Reader reader = new InputStreamReader(request.getInputStream())) {
            Gson gson = new Gson();
            return gson.fromJson(reader, Map.class);
        } catch (Exception e) {
           log.error(e.getMessage());
        }
        return null;
    }


    private void checkAccessToken(String access_token) throws RefreshTokenException {
        /* accessToken 의 검증 */
        try{
            jwtUtil.validateToken(access_token);
        } catch (ExpiredJwtException expiredJwtException) {
            //만료 기간이 지난 상황은 당연한 것이므로 로그만 출력
            log.info("Access token has expired");
        } catch (Exception exception) {
            throw new RefreshTokenException(RefreshTokenException.ErrorCase.NO_ACCESS);
        }
    }

    private Map<String, Object> checkRefreshToken(String refresh_token) throws RefreshTokenException {
        /* 리프레시 토큰을 검증하고 실패시 RefreshTokenException을 발생*/
        try {
            //매개 변수 refreshToken 을 받아 유효성 검사를 수행하고, 토큰에서 추출된 클레임(정보)을 Map으로 반환
            Map<String, Object> values = jwtUtil.validateToken(refresh_token);
            return values;
        } catch (ExpiredJwtException expiredJwtException) {
            //리프레시 토큰이 만료된 경우 -> OLD_REFRESH 예외발생
            throw new RefreshTokenException(RefreshTokenException.ErrorCase.OLD_REFRESH);
        } catch (Exception exception) {
            //리프레시 토큰이 없거나 잘못 전달된 상황
            exception.printStackTrace();
            throw new RefreshTokenException(RefreshTokenException.ErrorCase.NO_REFRESH);
        }
    }
}
