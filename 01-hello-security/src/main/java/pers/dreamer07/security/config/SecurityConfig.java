package pers.dreamer07.security.config;

import com.sun.org.apache.xpath.internal.operations.And;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import javax.sql.DataSource;

/**
 * Spring Security 配置类
 * @program: spring-security
 * @description:
 * @author: EMTKnight
 * @create: 2021-03-16
 **/
@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsService userDetailsService;
    @Autowired
    private DataSource dataSource;

    /**
     * 重写 configure(AuthenticationManagerBuilder auth) 创建一个用户
     * @param auth
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        // 通过 BCryptPasswordEncoder 密码加密接口对密码进行加密
//        String encode = new BCryptPasswordEncoder().encode("123456");
//        // inMemoryAuthentication()：将用户身份信息保存到内存中
//        auth.inMemoryAuthentication().withUser("geek").password(encode).roles("master");
        // 设置要使用的 userDetailsService 组件
        auth.userDetailsService(userDetailsService);
    }


    /**
     * 配置登录页面的请求拦截
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin() // 自定义配置登录表单
                .loginPage("/login.html") // 配置登录页面
                .loginProcessingUrl("/login") // 配置登录页面访问路径，底层由 Spring Security 实现
                .defaultSuccessUrl("/success.html") // 配置登录成功后跳转页面
                .permitAll() // 放行

            .and().authorizeRequests() // 自定义配置拦截请求
                .antMatchers("/", "/login", "/test/hello").permitAll() // 对匹配成功的路径放行(‘permitAll()’)
//                .anyRequest().authenticated() // 剩下的任何请求路径都需要认证
                /* 基于权限/角色进行访问控制 */
                .antMatchers("/test/index")
//                .hasAuthority("admin") // 在访问对应的资源必须有对应的权限(hasAuthority)
                .hasAnyAuthority("admin", "master") // 在访问对应的资源时只要有其中一个权限(hasAnyAuthority)
//                .hasRole("master") // 访问对应的资源时必须具有对应的角色(hasRole)
//                  .hasAnyRole("master", "admin") // 访问对应的资源时只要有其中一个角色即可(hasAnyRole)

            .and()
            .csrf().disable() // 关闭 csrf 的防护

            .exceptionHandling().accessDeniedPage("/unauth.html") // 配置没有权限时访问的页面

            .and().logout() // 配置注销设置
                .logoutUrl("/logout") // 设置注销请求地址，默认是 /logout
                .logoutSuccessUrl("/login.html").permitAll() // 设置注销后的跳转页面

            .and().rememberMe() // 配置记住我功能
                .tokenRepository(persistentTokenRepository()) // 配置使用的数据库操作对象
                .tokenValiditySeconds(60); // 配置数据库数据过时时长，单位为秒
    }

    /**
     * 将数据加密方式对应的实现类作为 Bean 注册到 IOC 容器中
     * @return
     */
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    /**
     * 创建实现记住我的数据库操作对象
     * @return
     */
    @Bean
    public PersistentTokenRepository persistentTokenRepository(){
        JdbcTokenRepositoryImpl jdbcTokenRepository = new JdbcTokenRepositoryImpl();
        jdbcTokenRepository.setDataSource(dataSource); // 配置数据源
        jdbcTokenRepository.setCreateTableOnStartup(true); // 在启动时自动建表,如果已经存在可以不配置
        return jdbcTokenRepository;
    }
}
