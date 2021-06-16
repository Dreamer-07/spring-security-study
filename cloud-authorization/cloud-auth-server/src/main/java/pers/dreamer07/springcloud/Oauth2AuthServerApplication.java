package pers.dreamer07.springcloud;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

/**
 * @program: cloud-authorization
 * @description:
 * @author: EMTKnight
 * @create: 2021-06-08
 **/
@EnableDiscoveryClient
@SpringBootApplication
public class Oauth2AuthServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(Oauth2AuthServerApplication.class, args);
    }

}
