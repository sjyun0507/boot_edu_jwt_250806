package com.yia0507.boot_edu_jwt_250806.security.filter;

import com.google.gson.Gson;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.Map;

/*
Spring Security 에서 JWT 로그인 인증을 처리하기 위한 커스텀 필터
클라이언트가 로그인할 때 전송한 JSON 형식의 아이디/비밀번호를 읽어서 Spring Security 인증 처리를 담당하는 역할
1. POST 로그인 요청 처리 :URL 경로가 /generateToken 이고, HTTP 메서드가 POST 일 때만 동작함
2. JSON 파싱 : 요청 본문에서 mid, mpw 값을 꺼냄 ({"mid": "아이디", "mpw": "비밀번호"} 형식)
3. Authentication 객체 생성 : UsernamePasswordAuthenticationToken 을 생성해 인증 시도
4. spring Security 인증 위임 : getAuthenticationManager().authenticate() 호출하여 Spring Security 에 인증 위임
 */
@Log4j2
public class APILoginFilter extends AbstractAuthenticationProcessingFilter {
    //이 필터가 어떤 URL 에서 작동할지 설정
    public APILoginFilter(String defaultFilterProcessesUrl) {
        super(defaultFilterProcessesUrl);
    }

    //로그인 요청을 가로채는 메서드
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {
        log.info("APILoginFilter-----");

        //GET 요청이면 무시하고 null 반환, 로그인은 POST 로만 처리해야 하므로, GET 요청은 거부함
        if(request.getMethod().equalsIgnoreCase("GET")){
            log.info("GET METHOD NOT SUPPORT");
            return null;
        }
        //JSON 요청 파싱 - 요청 본문(JSON)에서 로그인 정보 꺼냄.
        Map<String,String> requestJSON = parseRequestJSON(request);
        log.info("requestJSON:{}", requestJSON);

        //추가부분 :인증 토큰 객체 생성, Spring Security 에서 사용하는 아이디/비밀번호 기반 인증 객체 생성
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                requestJSON.get("mid"),
                requestJSON.get("mpw"));

        //Spring Security 에 인증 위임
        return getAuthenticationManager().authenticate(authenticationToken);
    }

    //JSON 파싱 메서드 - HTTP 요청 바디에 담긴 JSON 데이터를 파싱해서 Map으로 반환
    private Map<String, String> parseRequestJSON(HttpServletRequest request) {
        //JSON 데이터를 분석해서 mid, mpw 전달 값을 Map 으로 처리
        try (Reader reader = new InputStreamReader(request.getInputStream())) {
            Gson gson = new Gson();
            return gson.fromJson(reader, Map.class);
        } catch (Exception e) {
            log.error(e.getMessage());
        }
        return null;
    }

}

/*
[프론트엔드] → POST /generateToken (JSON: mid, mpw)
         ↓
[APILoginFilter] (요청 가로채기)
    - JSON 파싱
    - 인증 객체 생성
    - AuthenticationManager 에 인증 위임
         ↓
[Spring Security 내부 처리]
    - DB 사용자 조회 (UserDetailsService)
    - 비밀번호 비교
         ↓
인증 성공 → 다음 필터에서 JWT 발급
 */
