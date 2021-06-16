package pers.dreamer07.springcloud.authorization;

import cn.hutool.core.convert.Convert;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import pers.dreamer07.springcloud.constant.AuthConstant;
import pers.dreamer07.springcloud.constant.RedisConstant;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * @program: cloud-authorization
 * @description: 鉴权管理器
 * @author: EMTKnight
 * @create: 2021-06-10
 **/
@Component
public class AuthorizationManager implements ReactiveAuthorizationManager<AuthorizationContext> {

    @Autowired
    private RedisTemplate redisTemplate;

    @Override
    public Mono<AuthorizationDecision> check(Mono<Authentication> mono, AuthorizationContext authorizationContext) {
        AntPathMatcher antPathMatcher = new AntPathMatcher();
        // 从 redis 中获取当前资源的可访问角色列表
        URI uri = authorizationContext.getExchange().getRequest().getURI();
        Map<String, List<String>> resourceMap = redisTemplate.opsForHash().entries(RedisConstant.RESOURCE_ROLES_MAP);
        List<String> authorities = new ArrayList<>();
        for (Object key : resourceMap.keySet()) {
            if (antPathMatcher.match((String) key, uri.getPath())) {
                authorities = resourceMap.get(key);
                break;
            }
        }
        // 映射为 ROLE_+权限名 的格式
        authorities = authorities.stream().map(i -> i = AuthConstant.AUTHORITY_PREFIX + i).collect(Collectors.toList());
        return mono
                // 过滤留下当前用户已经认证的权限
                .filter(Authentication::isAuthenticated)
                // flux 响应式相关的操作，不太懂
                .flatMapIterable(Authentication::getAuthorities)
                .map(GrantedAuthority::getAuthority)
                // 如果用户的权限中有当前访问资源所需角色就返回一个 true，否则返回 false
                .any(authorities::contains)
                // 映射成对应的 AuthorizationDecision(授权决定)
                .map(AuthorizationDecision::new)
                // 如果上述结果为空就创建一个模块为 false 的授权决定
                .defaultIfEmpty(new AuthorizationDecision(false));
    }

}
