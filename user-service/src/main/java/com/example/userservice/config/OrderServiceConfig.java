package com.example.userservice.config;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;

@Getter
@Setter
@ToString
@ConfigurationProperties("order-service")
@RefreshScope
public class OrderServiceConfig {
    /* RestTemplate 방식으로 구현했을 때
    config 파일에서 url 값을 불러오기 위한 클래스 */
    private String url;

    @Getter
    @Setter
    public static class Exception {
        private String ordersIsEmpty;
    }
}
