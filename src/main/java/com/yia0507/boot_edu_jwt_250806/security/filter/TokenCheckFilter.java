package com.yia0507.boot_edu_jwt_250806.security.filter;

import com.yia0507.boot_edu_jwt_250806.security.exception.AccessTokenException;
import com.yia0507.boot_edu_jwt_250806.util.JWTUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;

@Log4j2
@RequiredArgsConstructor
public class TokenCheckFilter extends OncePerRequestFilter {
    private final JWTUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
    //특정 요청 경로에만 JWT 토큰 검사
        //클라이언트가 요청한 URI 경로
        String path = request.getRequestURI();

        //api 로 시작하지 않는 경로는 필터를 적용하지 않음
        if(!path.startsWith("/api")){
            filterChain.doFilter(request, response);
            return;
        }

        log.info("Token Check Filter........");
        log.info("JWTUtil:{}",jwtUtil);

        try{
            validateAccessToken(request);
            filterChain.doFilter(request, response);
        } catch (AccessTokenException accessTokenException) {
            accessTokenException.sendResponseError(response);
        }
//        filterChain.doFilter(request, response);
    }

    private Map<String, Object> validateAccessToken(HttpServletRequest request) throws AccessTokenException {
        /*
        HTTP 요청에서 JWT Access Token 을 검증
        검증에 실패하면 AccessTokenException 을 발생
         */
        //1. Authorization 정보가 잘못된 경우
        String headerStr = request.getHeader("Authorization");
        log.info("headerStr:{}",headerStr);

        // Authorization 헤더가 없거나 길이가 8자 미만('Bearer') 인 경우 예외 발생
        if(headerStr == null || headerStr.length() < 8){
            throw new AccessTokenException(AccessTokenException.TOKEN_ERROR.UNACCEPT);
        }
        // ex)Bearer eyJ0eXAi...
        String tokenType = headerStr.substring(0,6); //Authorization 헤더의 첫 6글자
        String tokenStr = headerStr.substring(7); //Bearer 생략해서 실제 토큰 문자열을 추춯

        //토큰타입이 Bearer가 아닌 경우 예외 발생
        if (!tokenType.equalsIgnoreCase("Bearer")) {
            throw new AccessTokenException(AccessTokenException.TOKEN_ERROR.BADTYPE);
        }

        //2.jwtUtil.validateToken()에서 예외가 발생하는 경우
        try {
            // 토큰을 실제로 검증 (jwtUtil.validateToken)하고 정상적인 경우 claim 데이터를 반환.
            Map<String, Object> values = jwtUtil.validateToken(tokenStr);
            return values;
        } catch (MalformedJwtException malformedJwtException) {
            // 형식이 잘못된 토큰 (403)
            log.error("MalformedJwtException----------------------");
            throw new AccessTokenException(AccessTokenException.TOKEN_ERROR.MALFORM);
        } catch (SignatureException signatureException) {
            // 서명이 위조된 토큰 (403)
            log.error("SignatureException----------------------");
            throw new AccessTokenException(AccessTokenException.TOKEN_ERROR.BADSIGN);
        } catch (ExpiredJwtException expiredJwtException) {
            // 만료된 토큰 (403)
            log.error("ExpiredJwtException----------------------");
            throw new AccessTokenException(AccessTokenException.TOKEN_ERROR.EXPIRED);
        }

    }
}
