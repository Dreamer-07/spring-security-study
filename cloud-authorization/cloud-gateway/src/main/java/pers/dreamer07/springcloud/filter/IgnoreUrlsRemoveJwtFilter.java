package pers.dreamer07.springcloud.filter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import pers.dreamer07.springcloud.config.IgnoreUrlsConfig;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.List;

/**
 * @program: cloud-authorization
 * @description: 配置白名单过滤器，保证访问白名单的接口时直接放行
 * @author: EMTKnight
 * @create: 2021-06-10
 **/
@Component
public class IgnoreUrlsRemoveJwtFilter implements WebFilter {

    @Autowired
    private IgnoreUrlsConfig ignoreUrlsConfig;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        // 获取请求路径
        URI uri = exchange.getRequest().getURI();
        // 创建一个 Ant 风格的匹配器
        AntPathMatcher antPathMatcher = new AntPathMatcher();
        // 遍历白名单
        List<String> urls = ignoreUrlsConfig.getUrls();
        for (String ignoreUrl : urls) {
            // 匹配请求路径和白名单路径
            if (antPathMatcher.match(ignoreUrl, uri.getPath())) {
                // 如果匹配成功就删除对应的请求头
                ServerHttpRequest request = exchange.getRequest().mutate().header("Authorization", "").build();
                // 重新构建 request 和 exchange
                ServerWebExchange buildExchange = exchange.mutate().request(request).build();
                return chain.filter(buildExchange);
            }
        }

        return chain.filter(exchange);
    }

}
