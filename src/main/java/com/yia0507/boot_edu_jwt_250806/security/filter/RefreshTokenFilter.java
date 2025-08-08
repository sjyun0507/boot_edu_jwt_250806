package com.yia0507.boot_edu_jwt_250806.security.filter;

import com.yia0507.boot_edu_jwt_250806.util.JWTUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

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

        //요청 경로가 refreshPath 와 일치하지 않으면 필터를 건너뜀
        // api/token/refresh 외의 경로는 Refresh Token 검사에서 제외
        if (!path.equals(refreshPath)) {
            log.info("skip refresh token filter....");
            filterChain.doFilter(request, response);
            return;
        }
        //요청 경로가 refreshPath 일 경우, 로그 출력
        log.info("Refresh token filter...run.....1");


    }
}
