package io.security.springsecuritypractice.security.configs;


import io.security.springsecuritypractice.security.handler.FormAccessDeniedHandler;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

@EnableWebSecurity //스프링 시큐리티 필터가 스프링 필터체인에 등록된다.
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

//    private final UserDetailsService userDetailsService;
    private final AuthenticationProvider authenticationProvider;

    private final AuthenticationSuccessHandler successHandler;
    private final AuthenticationFailureHandler failureHandler;

    private final AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> authenticationDetailsSource;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
                .requestMatchers("/css/**", "/images/**","/js/**", "/favicon.*","/*/icon-*").permitAll()
                .requestMatchers("/","/signup","/login*").permitAll()
                .requestMatchers("/user").hasAuthority("ROLE_USER")
                .requestMatchers("/manager").hasAuthority("ROLE_MANAGER")
                .requestMatchers("/admin").hasAuthority("ROLE_ADMIN")
                .anyRequest().authenticated()
        )
        .formLogin(form -> form
                .loginPage("/login").permitAll()
                .authenticationDetailsSource(authenticationDetailsSource)
                .successHandler(successHandler)
                .failureHandler(failureHandler)
        )
//        .userDetailsService(userDetailsService); //provider로 유저정보를 가져오게 되면 더이상 필요없음
        .authenticationProvider(authenticationProvider)
        .exceptionHandling(exception -> exception.accessDeniedHandler(new FormAccessDeniedHandler("/denied")));


        return http.build();
    }

//    @Bean
//    public PasswordEncoder passwordEncoder(){
//        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
//    }

    //패스워드 인코더를 통해 디비에서 계정정보를 가져와 매핑하기 때문에 필요없어짐
//    @Bean
//    public UserDetailsService userDetailsService(){
//        UserDetails user = User.withUsername("user").password("{noop}1111").roles("USER").build();
//        return new InMemoryUserDetailsManager(user);
//    }
}
