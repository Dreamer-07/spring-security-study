package pers.dreamer07.springcloud.point;

import com.alibaba.fastjson.JSONObject;
import net.minidev.json.JSONUtil;
import org.apache.http.HttpHeaders;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import pers.dreamer07.springcloud.api.CommonResult;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

/**
 * @program: cloud-authorization
 * @description: 处理 token 过期/错误/未认证
 * @author: EMTKnight
 * @create: 2021-06-10
 **/
@Component
public class RestAuthenticationEntryPoint implements ServerAuthenticationEntryPoint {

    @Override
    public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException e) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
        String body = JSONObject.toJSONString(CommonResult.builder()
                .message(e.getMessage()).code(HttpStatus.UNAUTHORIZED.value()).build()
        );
        DataBuffer buffer = response.bufferFactory().wrap(body.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(buffer));
    }

}
