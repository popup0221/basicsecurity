package io.security.basicsecurity;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;

@Configuration
public class SecurityConfig {
   /*
    * ===============================================================================
    * issue - deprecated WebSecurityConfigurerAdapter
    * ===============================================================================
    * Spring Security 5.7.0-M2 이전
    * WebSecurityConfigurerAdapter 상속 후, configure 메소드를 오버라이딩 하여 설정하는 방식
    * ===============================================================================
    * Spring Security 5.7.0-M2 이후
    * SecurityFilterChain 를 빈으로 등록하는 방식
    * ===============================================================================
    */

    // FilterChainProxy에 configurer 등록

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // 인가정책
        http
                // authorizeHttpRequests() : 요청에대한 보안검사 시작
                .authorizeHttpRequests(authorizationManagerRequestMatcherRegistry ->
                        // anyRequest().authenticated() : 어떠한 요청이든 인증을 받음
                        authorizationManagerRequestMatcherRegistry.anyRequest().authenticated()
                );

        // 인증정책
        http
                .formLogin() // 폼 로그인 방식
//                .loginPage("/loginPage") // 사용자 정의 로그인 페이지
//                .defaultSuccessUrl("/") // 로그인 성공 후 이동 페이지
//                .failureUrl("/login") // 로그인 실패 후 이동 페이지
                .usernameParameter("userId") // 아이디 파라미터명 설정
                .passwordParameter("pwd") // 패스워드 파라미터명 설정
                .loginProcessingUrl("/login-process") // 로그인 Form Action URL
                .successHandler(new AuthenticationSuccessHandler() { // 로그인 성공 후 핸들러
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        System.out.println("authentication : " + authentication.getName());
                        response.sendRedirect("/main");
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() { // 로그인 실패 후 핸들러
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        System.out.println("exception : " + exception.getMessage());
                        response.sendRedirect("/login");
                    }
                })
                .permitAll(); // 로그인 URL -> 모든인증 허용

        return http.build();
    }


}
