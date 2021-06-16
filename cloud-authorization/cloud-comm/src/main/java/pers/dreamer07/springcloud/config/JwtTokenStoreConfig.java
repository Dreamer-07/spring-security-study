package pers.dreamer07.springcloud.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.rsa.crypto.KeyStoreKeyFactory;

import java.security.KeyPair;

/**
 * @program: cloud-authorization
 * @description: 使用 jwt 存储 token 的配置
 * @author: EMTKnight
 * @create: 2021-06-09
 **/
@Configuration
public class JwtTokenStoreConfig {

    @Primary
    @Bean
    public TokenStore jwtTokenStore() {
        return new JwtTokenStore(jwtAccessTokenConverter());
    }

    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        converter.setSigningKey("byqtxdy");
        converter.setKeyPair(keyPair());
        return converter;
    }

    /**
     * 配置 jwt 密钥对
     * @return
     */
    @Bean
    public KeyPair keyPair() {
        // 从classpath下的证书中获取证书库中的数据
        KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(new ClassPathResource("jwt.jks"), "123456".toCharArray());
        // 获取指定的密钥对
        return keyStoreKeyFactory.getKeyPair("jwt", "123456".toCharArray());
    }

}
