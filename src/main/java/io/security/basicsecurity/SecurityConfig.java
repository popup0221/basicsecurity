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
                /**
                 * Authenticateion Api - FormLogin(폼 로그인 방식)
                 * 1. login request
                 * 2. UsernamePassWordAuthenticationFilter
                 * 3. AntPathRequestMatcher(/loginURL)에서 요청 경로가 매칭되는지 확인
                 * 4. Y -> Authentication(username + password) 생성 후 {AuthenticationManager}에 전달
                 *    N -> next filter chain.doFilter
                 * 5. {AuthenticationManager}는 {AuthenticationProvider}에 인증처리 위임
                 * 6. AuthenticationProvider
                 *      인증성공 -> {AuthenticationManager}에서 Authentication(User객체 + Authorities(권한 정보)) 생성
                 *      인증실패 -> AuthenticationException 발생, failureHandler 실행 또는 {failureUrl}로 리턴
                 * 7. 생성한 Authentication 객체를 {SecurityContext}에 저장 -> Session
                 * 8. SuccessHandler 실행 또는 {defaultSuccessUrl}로 리턴
                 */
                .formLogin(httpSecurityFormLoginConfigurer -> {
                    // 로그인 성공 후 핸들러
                    // 로그인 실패 후 핸들러
                    httpSecurityFormLoginConfigurer
                            .loginPage("/loginPage") // 사용자 정의 로그인 페이지
                            .defaultSuccessUrl("/") // 로그인 성공 후 이동 페이지
                            .failureUrl("/login") // 로그인 실패 후 이동 페이지
                            .usernameParameter("userId") // 아이디 파라미터명 설정
                            .passwordParameter("pwd") // 패스워드 파라미터명 설정
                            .loginProcessingUrl("/login-process") // 로그인 Form Action URL
                            .successHandler((request, response, authentication) -> {
                                System.out.println("authentication : " + authentication.getName());
                                response.sendRedirect("/main");
                            })
                            .failureHandler((request, response, exception) -> {
                                System.out.println("exception : " + exception.getMessage());
                                response.sendRedirect("/login");
                            })
                            .permitAll(); // 로그인 URL -> 모든인증 허용
                });

        return http.build();
    }

}
