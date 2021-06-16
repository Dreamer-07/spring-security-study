package pers.dreamer07.springcloud.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * @program: cloud-authorization
 * @description: 配置可以直接访问的路径及表单登录
 * @author: EMTKnight
 * @create: 2021-06-08
 **/
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    /**
     *  如果不配置 SpringBoot 会自动配置一个 AuthenticationManager,覆盖掉内存中的用户
     */
    @Bean
    @Override
    protected AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }

    /**
     * 配置访问路径
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .csrf().disable() // 关闭 csrf
            .authorizeRequests() // 配置直接访问的路径
                .antMatchers("/oauth/**", "/login/**", "/logout/**", "/rsa/publicKey").permitAll()
                .anyRequest().authenticated()
            .and().formLogin().permitAll(); // 开启表单登录
    }


}
