package pers.dreamer07.springcloud.config;

import cn.hutool.core.util.ArrayUtil;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import pers.dreamer07.springcloud.authorization.AuthorizationManager;
import pers.dreamer07.springcloud.constant.AuthConstant;
import pers.dreamer07.springcloud.filter.IgnoreUrlsRemoveJwtFilter;
import pers.dreamer07.springcloud.point.RestAuthenticationEntryPoint;
import pers.dreamer07.springcloud.point.RestfulAccessDeniedPoint;
import reactor.core.publisher.Mono;

import java.util.Arrays;

/**
 * @program: cloud-authorization
 * @description: 网关服务进行安全配置
 * @author: EMTKnight
 * @create: 2021-06-10
 **/
@AllArgsConstructor
@Configuration
@EnableWebFluxSecurity
@Slf4j
public class ResourceServerConfig {

    private IgnoreUrlsConfig ignoreUrlsConfig;

    private RestAuthenticationEntryPoint restAuthenticationEntryPoint;

    private RestfulAccessDeniedPoint restfulAccessDeniedPoint;

    private IgnoreUrlsRemoveJwtFilter ignoreUrlsRemoveJwtFilter;

    private AuthorizationManager authorizationManager;

    /**
     * 配置 Security Web 拦截器链
     * @param http
     * @return
     */
    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http){
        http.oauth2ResourceServer().jwt().jwtAuthenticationConverter(jwtAuthenticationConverter());
        // 定义 JWT 请求头过期或签名错误的处理
        http.oauth2ResourceServer().authenticationEntryPoint(restAuthenticationEntryPoint);
        // 针对白名单路径，直接移除JWT请求头
        http.addFilterBefore(ignoreUrlsRemoveJwtFilter, SecurityWebFiltersOrder.AUTHENTICATION);
        http.authorizeExchange()
                // 配置白名单放行
                .pathMatchers(ArrayUtil.toArray(ignoreUrlsConfig.getUrls(), String.class)).permitAll()
                // 配置鉴权管理器
                .anyExchange().access(authorizationManager)
                // 配置异常的拦截器链
                .and().exceptionHandling()
                    .accessDeniedHandler(restfulAccessDeniedPoint)  // 处理未授权
                    .authenticationEntryPoint(restAuthenticationEntryPoint)  // 处理未认证
                .and().csrf().disable();
        return http.build();
    }

    /**
     * 配置使用 jwt 进行认证的转换器
     * @return
     */
    @Bean
    public Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>> jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        jwtGrantedAuthoritiesConverter.setAuthorityPrefix(AuthConstant.AUTHORITY_PREFIX);
        jwtGrantedAuthoritiesConverter.setAuthoritiesClaimName(AuthConstant.AUTHORITY_CLAIM_NAME);
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter);
        return new ReactiveJwtAuthenticationConverterAdapter(jwtAuthenticationConverter);
    }
}
