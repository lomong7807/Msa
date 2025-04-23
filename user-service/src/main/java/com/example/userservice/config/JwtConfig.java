package com.example.userservice.config;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;

@Getter
@Setter
@ToString
@ConfigurationProperties("token")
@RefreshScope
public class JwtConfig {
    private String expiration_time;
    private String secret;
}
