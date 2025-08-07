package com.yia0507.boot_edu_ex_security_250724.config;

import com.yia0507.boot_edu_ex_security_250724.security.CustomUserDetailsService;
import com.yia0507.boot_edu_ex_security_250724.security.handler.Custom403Handler;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import javax.sql.DataSource;

@Log4j2
@Configuration
@EnableMethodSecurity
@RequiredArgsConstructor
public class CustomSecurityConfig {
    private final DataSource dataSource;
    private final CustomUserDetailsService customUserDetailsService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        //spring security 의 설정을 담당하는 메서드
        log.info("----------Security Config----------");

        //spring security 에서 폼 기반 로그인을 설정
        httpSecurity.formLogin(config -> {
            config.loginPage("/member/login");

        });

        httpSecurity.csrf(csrf -> csrf.disable());
        //Spring Security 설정에서 CSRF(Cross-Site Request Forgery) 보호 기능을 비활성화

        httpSecurity.rememberMe(remeberMe -> {
            remeberMe.key("12345678") //토큰 무결성 확인용 키
                    .tokenRepository(persistentTokenRepository())
                    .userDetailsService(customUserDetailsService)
                    .tokenValiditySeconds(60 * 60 * 24 * 60); //60일 동안 유효
        });

        httpSecurity.exceptionHandling(exception -> {
            exception.accessDeniedHandler(accessDeniedHandler());
        });

        httpSecurity.oauth2Login(config -> {
            config.loginPage("/member/login");
        });

        return httpSecurity.build();
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
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public PersistentTokenRepository persistentTokenRepository() {
        /* Spring Security 에서 remember-me 기능을 위한 Persistent Token 저장소를 설정*/
        JdbcTokenRepositoryImpl repository = new JdbcTokenRepositoryImpl();
        repository.setDataSource(dataSource); // DB 연결
        return repository;
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return new Custom403Handler();
    }
}













