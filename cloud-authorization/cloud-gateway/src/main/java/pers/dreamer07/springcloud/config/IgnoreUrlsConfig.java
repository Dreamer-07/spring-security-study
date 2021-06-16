package pers.dreamer07.springcloud.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * @program: cloud-authorization
 * @description: 配置网关白名单
 * @author: EMTKnight
 * @create: 2021-06-10
 **/
@Data
@Component
@ConfigurationProperties(prefix = "secure.ignore")
public class IgnoreUrlsConfig {

    private List<String> urls;

}
