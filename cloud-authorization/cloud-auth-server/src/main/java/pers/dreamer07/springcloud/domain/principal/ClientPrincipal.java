package pers.dreamer07.springcloud.domain.principal;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.provider.ClientDetails;
import pers.dreamer07.springcloud.constant.MessageConstant;
import pers.dreamer07.springcloud.domain.pojo.Client;

import java.util.*;

/**
 * @program: cloud-authorization
 * @description: 业务中实际使用的 Client 客户端信息类
 * @author: EMTKnight
 * @create: 2021-06-10
 **/
@Data
@NoArgsConstructor
@AllArgsConstructor
public class ClientPrincipal implements ClientDetails {

    private Client client;

    @Override
    public String getClientId() {
        return client.getClientId();
    }

    @Override
    public Set<String> getResourceIds() {
        return new HashSet<>(Arrays.asList(client.getResourceIds().split(MessageConstant.SPLIT_COMMA)));
    }

    @Override
    public boolean isSecretRequired() {
        return client.getSecretRequire();
    }

    @Override
    public String getClientSecret() {
        return client.getClientSecret();
    }

    @Override
    public boolean isScoped() {
        return client.getScopeRequire();
    }

    @Override
    public Set<String> getScope() {
        return new HashSet<>(Arrays.asList(client.getScope().split(MessageConstant.SPLIT_COMMA)));
    }

    @Override
    public Set<String> getAuthorizedGrantTypes() {
        return new HashSet<>(Arrays.asList(client.getAuthorizedGrantTypes().split(MessageConstant.SPLIT_COMMA)));
    }

    @Override
    public Set<String> getRegisteredRedirectUri() {
        return new HashSet<>(Arrays.asList(client.getWebServerRedirectUri().split(MessageConstant.SPLIT_COMMA)));
    }

    @Override
    public Collection<GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collection = new ArrayList<>();
        Arrays.asList(client.getAuthorities().split(MessageConstant.SPLIT_COMMA)).forEach(
                auth -> collection.add((GrantedAuthority) () -> auth)
        );
        return collection;
    }

    @Override
    public Integer getAccessTokenValiditySeconds() {
        return client.getAccessTokenValidity();
    }

    @Override
    public Integer getRefreshTokenValiditySeconds() {
        return client.getRefreshTokenValidity();
    }

    @Override
    public boolean isAutoApprove(String scope) {
        return false;
    }

    @Override
    public Map<String, Object> getAdditionalInformation() {
        return null;
    }
}
