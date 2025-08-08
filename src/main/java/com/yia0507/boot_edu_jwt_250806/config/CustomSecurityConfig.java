package com.yia0507.boot_edu_jwt_250806.config;

import com.yia0507.boot_edu_jwt_250806.security.APIUserDetailsService;
import com.yia0507.boot_edu_jwt_250806.security.filter.APILoginFilter;
import com.yia0507.boot_edu_jwt_250806.security.filter.RefreshTokenFilter;
import com.yia0507.boot_edu_jwt_250806.security.filter.TokenCheckFilter;
import com.yia0507.boot_edu_jwt_250806.security.handler.APILoginSuccessHandler;
import com.yia0507.boot_edu_jwt_250806.util.JWTUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Log4j2
@Configuration
@EnableMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class CustomSecurityConfig {
    private final APIUserDetailsService apiUserDetailsService;
    private final JWTUtil jwtUtil;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        //spring security 에서 정적 리소스나 보안 필터 제외 대상을 설정할 때 사용
        log.info("----------Web configure----------");

        //정적 파일 경로에 시큐리티 적용을 안함
        return (web) ->
                web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        log.info("------------configure-------------------");

        // CSRF 토큰의 비활성화
        http.csrf(httpSecurityCsrfConfigurer -> {
            httpSecurityCsrfConfigurer.disable();
        });

        // 세션을 사용하지 않음
        http.sessionManagement(httpSecuritySessionManagement -> {
            httpSecuritySessionManagement.sessionCreationPolicy(SessionCreationPolicy.NEVER);
        });

        //1. AuthenticationManagerBuilder 가져오기 (Spring Security 내부 객체)
        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);

        //2. 사용자 인증 정보 구성(UserDetailsService + PasswordEncoder)
        //apiUserDetailsService : 사용자 인증 시 로그인 정보를 불러올 서비스
        authenticationManagerBuilder
                .userDetailsService(apiUserDetailsService)
                .passwordEncoder(passwordEncoder());

        //3. AuthenticationManager 생성
        AuthenticationManager authenticationManager = authenticationManagerBuilder.build();

        //4. security 설정에 AuthenticationManager 명시적으로 등록
        http.authenticationManager(authenticationManager);

        //5. APILoginFilter 생성 및 AuthenticationManager 설정
        //APILoginFilter 는 로그인 요청을 처리하는 필터로,"/generateToken"경로에 대한 요청을 처리
        //apiLoginFilter-> /generateToken 경로로 요청 시 동작할 커스텀 로그인 필터
        APILoginFilter apiLoginFilter = new APILoginFilter("/generateToken");
        apiLoginFilter.setAuthenticationManager(authenticationManager);

        //APILoginSuccessHandler
        APILoginSuccessHandler successHandler = new APILoginSuccessHandler(jwtUtil);
        //SuccessHandler 세팅
        apiLoginFilter.setAuthenticationSuccessHandler(successHandler);

        //6. APILoginFilter 를 UsernamePasswordAuthenticationFilter 보다 먼저 적용
        //APILoginfilter 의 위치조정, 기본 로그인 필터보다 먼저 실행되도록 필터 체인에 삽입
        http.addFilterBefore(apiLoginFilter, UsernamePasswordAuthenticationFilter.class);

        // API로 시작하는 모든 경로는 TokenCheckFilter 동작
        http.addFilterBefore(tokenCheckFilter(jwtUtil), UsernamePasswordAuthenticationFilter.class);

        //refreshToken 호출 처리
        http.addFilterBefore(new RefreshTokenFilter("/refreshToken", jwtUtil),
                TokenCheckFilter.class
        );

        return http.build();
    }

    private TokenCheckFilter tokenCheckFilter(JWTUtil jwtUtil) {
        return new TokenCheckFilter(jwtUtil);
    }
}






