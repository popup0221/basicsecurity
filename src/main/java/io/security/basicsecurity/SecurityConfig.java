package io.security.basicsecurity;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
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
                 * Authenticateion API - FormLogin(폼 로그인 방식)
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
                 *
                 * Tip - {defaultSuccessUrl}은 우선순위가 제일 마지막이다.
                 *
                 * 스프링 시큐리티는 {SaveRequest}와 {RequestCache}를 통해 로그인 직전 URL 정보를
                 * 기억하고 있다가 성공 시 그 경로를 우선적으로 {redirect}한다.
                 *
                 * 이러한 이유로 로그아웃 시 세션정보가 사라져 {SaveRequest}와 {RequestCache}에서 URL 정보를 얻지 못한다.
                 *
                 * defaultSuccessUrl("/", true) -> 두번째 인자로 true 값을 주었을 때, (기본값 false)
                 * 로그인을 성공한 다음 무조건 {defaultSuccessUrl}에서 설정한 경로로 이동한다.
                 *
                 * 기본 값이라는 것은 특별한 설정을 하지 않을 경우 오류가 나거나 null 값을 가지지 않도록 하기 위한 목적으로 사용하기 때문에
                 * 특별한 이유가 없으면 SuccessHandler 를 사용해서 직접 리다이렉트 하는 방식이 좋다.
                 */
                .formLogin(httpSecurityFormLoginConfigurer -> {
                    // 로그인 성공 후 핸들러
                    // 로그인 실패 후 핸들러
                    httpSecurityFormLoginConfigurer
//                            .loginPage("/login") // 사용자 정의 로그인 페이지
//                            .defaultSuccessUrl("/") // 로그인 성공 후 이동 페이지
//                            .failureUrl("/login") // 로그인 실패 후 이동 페이지
                            .usernameParameter("userId") // 아이디 파라미터명 설정
                            .passwordParameter("pwd") // 패스워드 파라미터명 설정
                            .loginProcessingUrl("/login-process") // 로그인 Form Action URL
                            .successHandler((request, response, authentication) -> {
                                System.out.println("authentication : " + authentication.getName());
                                response.sendRedirect("/");
                            })
                            .failureHandler((request, response, exception) -> {
                                System.out.println("exception : " + exception.getMessage());
                                response.sendRedirect("/login");
                            })
                            .permitAll(); // 로그인 URL -> 모든인증 허용
                })

                /**
                 * Authenticateion API - Logout(로그아웃)
                 * 세션 무효화, 인증토큰 삭제, 쿠키정보 삭제, 로그인 페이지로 리다이렉트
                 * 1. Logout Request (POST 방식)
                 * 2. LogoutFilter
                 * 3. AntPathRequestMatcher(/logoutURL)에서 요청 경로가 매칭되는지 확인
                 * 4. Y -> {SecurityContext}에서 {Authentication}객체를 {SecurityContextLogoutHandler}로 전달
                 *    N -> next filter chain.doFilter
                 * 5. SecurityContextLogoutHandler
                 *      5-1. 세션 무효화
                 *      5-2. 쿠키 삭제
                 *      5-3. SecurityContextHolder.clearContext() // 인증객체(인증토큰) 초기화
                 * 6. SecurityContextLogoutHandler 종료 후 -> SimpleUrlLogoutSuccessHandler 살행
                 */
                .logout(httpSecurityLogoutConfigurer -> {
                    httpSecurityLogoutConfigurer
                            .logoutUrl("/logout") // 로그아웃 처리 URL
                            .logoutSuccessUrl("/login") // 로그아웃 성공 후 이동할 페이지 URL
                            .addLogoutHandler((request, response, authentication) -> {
                                HttpSession session = request.getSession();
                                session.invalidate();
                            })
                            .logoutSuccessHandler((request, response, authentication) -> {
                                response.sendRedirect("/login");
                            })
                            .deleteCookies("remember-me"); // 로그아웃 후 쿠키 삭제
                });

        return http.build();
    }

}
