package pers.dreamer07.springcloud.point;

import com.alibaba.fastjson.JSONObject;
import com.google.common.net.HttpHeaders;
import net.minidev.json.JSONUtil;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import pers.dreamer07.springcloud.api.CommonResult;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

/**
 * @program: cloud-authorization
 * @description: 访问权限不够时
 * @author: EMTKnight
 * @create: 2021-06-10
 **/
@Component
public class RestfulAccessDeniedPoint implements ServerAccessDeniedHandler {

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, AccessDeniedException exception) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.FORBIDDEN);
        response.getHeaders().add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
        String body = JSONObject.toJSONString(CommonResult.builder()
                .message(exception.getMessage()).code(HttpStatus.FORBIDDEN.value()).build()
        );
        DataBuffer buffer = response.bufferFactory().wrap(body.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(buffer));
    }

}
