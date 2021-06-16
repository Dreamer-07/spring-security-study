package pers.dreamer07.springcloud.domain.pojo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import org.springframework.security.oauth2.provider.ClientDetails;

import java.util.Map;
import java.util.Set;

/**
 * @program: cloud-authorization
 * @description: 存储客户端信息的实体类
 * @author: EMTKnight
 * @create: 2021-06-10
 **/
@Data
@EqualsAndHashCode(callSuper = false)
@AllArgsConstructor
@Builder(toBuilder = true)
public class Client{

    /**
     * 客户端 id
     */
    private String clientId;

    /**
     * 资源 id
     */
    private String resourceIds;

    /**
     * 是否必须携带 client-secret
     */
    private Boolean secretRequire;

    /**
     * client-secret
     */
    private String clientSecret;

    /**
     * 是否必须携带范围
     */
    private Boolean scopeRequire;

    /**
     * 范围
     */
    private String scope;

    /**
     * 支持的认证类型
     */
    private String authorizedGrantTypes;

    /**
     * 用于授权成功后跳转
     */
    private String webServerRedirectUri;


    private String authorities;

    /**
     * 令牌的过期时间
     */
    private Integer accessTokenValidity;

    /**
     * 刷新令牌的过期时间
     */
    private Integer refreshTokenValidity;
}
