package io.security.basicsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

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

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // 인가정책
        http
                .authorizeRequests() // 요청에대한 보안검사 시작
                .anyRequest().authenticated(); // 어떠한 요청이든 인증을 받음

        // 인증정책
        http
                .formLogin(); // 폼 로그인 방식

        return http.build();
    }


}
