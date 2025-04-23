package com.example.apigatewayservice.filter;

import com.example.apigatewayservice.config.EnvConfig;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

@Component
@Slf4j
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {

    Environment env;
    EnvConfig envConfig;


    public AuthorizationHeaderFilter(Environment env, EnvConfig envConfig) {
        super(Config.class);
        this.env = env;
        this.envConfig = envConfig;
    }

    public static class Config {

    }

    // login -> token -> users(with token) -> header(include token)
    @Override
    public GatewayFilter apply(Config config) {
        // Custom Pre Filter
        return (exchange, chain) -> {
            // Import RxJava server.reactive
            ServerHttpRequest request = exchange.getRequest();

            // JWT 인증 후 request header 에 포함하여 반환해준 AUTHORIZATION 이 없다면 에러
            if(!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)){
                return onError(exchange, "No authorization header", HttpStatus.UNAUTHORIZED);
            }

            // request header 에 AUTHORIZATION 이 있다면 가져옴
            String authorizationHeader = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
            // JWT token 에는 Bearer 라는 값을 가지고 오는데, 이걸 빈 문자열로 바꾸고 JWT token 값만 확인
            String jwt = authorizationHeader.replace("Bearer ", "");

            if(!isJwtValid(jwt)){
                return onError(exchange, "JWT token is not valid", HttpStatus.UNAUTHORIZED);
            }

            return chain.filter(exchange).then(Mono.fromRunnable(() -> {
            }));
        };
    }

    // Mono, Flux -> Spring WebFlux
    private Mono<Void> onError(ServerWebExchange exchange, String errMsg, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);

        log.error(errMsg);

        return response.setComplete();
    }

    private boolean isJwtValid(String jwt) {
        boolean returnValue = true;

        String subject = null;

        log.error("expiration_time: " + envConfig.getExpiration_time());
        log.error("secret: " + envConfig.getSecret());
        log.error("env.secret: " + env.getProperty("token.secret"));
        log.error("env.expiration_time: " + env.getProperty("token.expiration_time"));

        try{
            /*
            * Keys.hmacShaKeyFor: 바이트 배열을 HMAC-SHA 알고리즘에 사용할 수 있는 보안 키로 변환
            * parseClaimsJws(): JJWT 라이브러리에서 서명된 JWT 인지 파싱하고 검증함
            * subject(): 그 안에 담긴 정보를 추출한다
            * */
            subject = Jwts.parserBuilder()
                    .setSigningKey(Keys.hmacShaKeyFor(envConfig.getSecret().getBytes(StandardCharsets.UTF_8)))
                    .build()
                    .parseClaimsJws(jwt)
                    .getBody()
                    .getSubject();

        }catch (Exception e) {
            returnValue = false;
        }

        if(subject == null || subject.isEmpty()) {
            returnValue = false;
        }

        return returnValue;
    }
}
