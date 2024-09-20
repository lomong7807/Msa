package com.example.userservice.security;


import com.example.userservice.service.UserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class WebSecurity{

    private UserService userService;
    private BCryptPasswordEncoder passwordEncoder;
    private Environment env;

    public WebSecurity(UserService userService,
                       BCryptPasswordEncoder passwordEncoder,
                       Environment env) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
        this.env = env;
    }

    @Bean
    protected SecurityFilterChain configure(HttpSecurity http) throws Exception{

        // Configure AuthenticationManagerBuilder
        AuthenticationManagerBuilder authenticationManagerBuilder =
                http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.userDetailsService(userService).passwordEncoder(passwordEncoder);

        AuthenticationManager authenticationManager = authenticationManagerBuilder.build();

        http.csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers(new AntPathRequestMatcher("/actuator/**")).permitAll()
                        .requestMatchers(new AntPathRequestMatcher("/h2-console/**")).permitAll()
                        .requestMatchers(new AntPathRequestMatcher("/users")).permitAll()
                        .requestMatchers(new AntPathRequestMatcher("/welcome")).permitAll()
                        .requestMatchers(new AntPathRequestMatcher("/health_check/**")).permitAll()
                        .requestMatchers(new AntPathRequestMatcher("/user-service/**")).permitAll()
                        .requestMatchers("/**").access(
                                new WebExpressionAuthorizationManager("hasIpAddress('localhost') or hasIpAddress('127.0.0.1') or hasIpAddress('172.30.96.94')")) // host pc ip address
                        .anyRequest().authenticated()
                )
                .authenticationManager(authenticationManager)
                .sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilter(getAuthenticationFilter(authenticationManager))
                .headers((header) -> header.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin));
        return http.build();
    }

    public AuthenticationManager authenticationManager(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userService).passwordEncoder(passwordEncoder);
        return auth.build();
    }

    private AuthenticationFilter getAuthenticationFilter(AuthenticationManager authenticationManager) throws Exception{
        AuthenticationFilter authenticationFilter = new AuthenticationFilter();

        return new AuthenticationFilter(authenticationManager, userService, env);
    }

}
