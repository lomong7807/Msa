package com.example.userservice.config;

import lombok.RequiredArgsConstructor;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class SwaggerConfig {
    @Bean
    public GroupedOpenApi customTestOpenApi() {
        String[] paths = new String[] { "/users/**", "/welcome", "/user-service/health_check" };

        return GroupedOpenApi.builder()
                .group("일반 사용자 관리를 위한 User 도메인에 대한 API")
                .pathsToMatch(paths)
                .build();
    }
}
