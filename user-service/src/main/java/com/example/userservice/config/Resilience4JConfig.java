package com.example.userservice.config;

import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.timelimiter.TimeLimiterConfig;
import org.springframework.cloud.circuitbreaker.resilience4j.Resilience4JCircuitBreakerFactory;
import org.springframework.cloud.circuitbreaker.resilience4j.Resilience4JConfigBuilder;
import org.springframework.cloud.client.circuitbreaker.Customizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;

@Configuration
public class Resilience4JConfig {

    @Bean
    public Customizer<Resilience4JCircuitBreakerFactory> globalCustomConfiguration() {
        /*
        * failureRateThreshold: CircuitBreaker를 열지 결정하는 failureRate threshold percentage
        * - default: 50%
        * waitDurationInOpenState: CircuitBreaker를 open한 상태를 유지하는 지속 기간을 의미
        * - 이 기간 이후에 half-open 상태
        * - default: 60seconds
        * slidingWindowType: CircuitBreaker가 닫힐 때 통화 결과를 기록하는 데 사용되는 슬라이딩 창의 유형을 구성
        * - e.g. 10
        * - 카운트 기반 또는 시간 기반
        * - default: COUNT_BASED
        * slidingWindowSize: CircuitBreaker가 닫힐 때 호출 결과를 기록하는 데 사용되는 슬라이딩 창의 크기를 구성
        * - default: 100
        * */
        /*
        * 아래 설정
        * 1. open한 상태를 1초 동안 유지한다.
        * 2. 최근 2개의 요청 결과를 분석한다.
        * 3. 최근 2개의 요청 중에서 실패율이 400%를 초과하면 서킷브레이커가 OPEN 으로 전환된다.
        *   - 하지만 실패율은 논리적으로 100%를 넘을 수 없다.
        *   - 따라서 이 설정에서는 2개의 요청 중 1개라도 실패하면(50% 실패율) OPEN 상태로 전환
        * */
        CircuitBreakerConfig circuitBreakerConfig = CircuitBreakerConfig.custom()
                .failureRateThreshold(4)
                .waitDurationInOpenState(Duration.ofMillis(1000))
                .slidingWindowType(CircuitBreakerConfig.SlidingWindowType.COUNT_BASED)
                .slidingWindowSize(2)
                .build();

        TimeLimiterConfig timeLimiterConfig = TimeLimiterConfig.custom()
                .timeoutDuration(Duration.ofSeconds(4))
                .build();

        return factory -> factory.configureDefault(id -> new Resilience4JConfigBuilder(id)
                .timeLimiterConfig(timeLimiterConfig)
                .circuitBreakerConfig(circuitBreakerConfig)
                .build()
        );
    }
}
