package pers.dreamer07.springcloud.service.impl;

import cn.hutool.core.collection.CollUtil;
import org.apache.commons.collections4.CollectionUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import pers.dreamer07.springcloud.constant.MessageConstant;
import pers.dreamer07.springcloud.domain.pojo.Client;
import pers.dreamer07.springcloud.domain.principal.ClientPrincipal;

import javax.annotation.PostConstruct;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @program: cloud-authorization
 * @description: 用户加载客户端信息
 * @author: EMTKnight
 * @create: 2021-06-10
 **/
@Service
public class ClientDetailsServiceImpl implements ClientDetailsService {

    private List<Client> clientList;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostConstruct
    public void initData() {
        // 加密密码
        String clientSecret = passwordEncoder.encode("123456");
        clientList = new ArrayList<>();
        // 1、密码模式和授权码模式
        clientList.add(Client.builder()
                .clientId("client-app") // 客户端 id
                .resourceIds("oauth2-resource")
                .secretRequire(true)
                .clientSecret(clientSecret) // 客户端 secret
                .scopeRequire(true)
                .scope("all") // 申请访问
                .authorizedGrantTypes("authorization_code,password,refresh_token") // 配置授权模式
                .webServerRedirectUri("http://www.baidu.com")
                .authorities("master")
                .accessTokenValidity(3600) // 令牌有效期
                .refreshTokenValidity(86400).build()); // 刷新令牌的有效期
    }

    @Override
    public ClientDetails loadClientByClientId(String clientId) throws ClientRegistrationException {
        List<Client> findClientList = this.clientList.stream()
                .filter(client -> client.getClientId().equals(clientId))
                .collect(Collectors.toList());
        if (CollUtil.isEmpty(findClientList)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, MessageConstant.NOT_FOUND_CLIENT);
        }
        return new ClientPrincipal(findClientList.get(0));
    }

}
