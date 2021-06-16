package pers.dreamer07.security.controller;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import pers.dreamer07.security.pojo.User;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * @program: spring-security
 * @description:
 * @author: EMTKnight
 * @create: 2021-03-16
 **/
@RestController
@RequestMapping("/test")
public class HelloController {

    @GetMapping("/hello")
    public String hello(){
        return "hello";
    }

    @GetMapping("/index")
    public String index(){
        return "index";
    }

    /*
    * @Secured: 只有主体具有对应 value 中的任一角色才可以访问该请求
    *   - value: String[] 可以配置多个角色，但需要以 ROLE_ 开头
    * @PreAuthorize: 在调用对应的方法前执行，根据 value 值判断用户是否满足对应的权限/角色
    * @PostAuth: 在调用对应的方法之后执行，根据 value 值判断用户是否满足对应的权限/角色
    * */
//    @Secured({"ROLE_master", "ROLE_admin"})
//    @PreAuthorize("hasAuthority('master')")
    @PostAuthorize("hasAnyAuthority('master')")
    @GetMapping("/secured")
    public String getSecured(){
        System.out.println("update....");
        return "has role master or admin";
    }

    /* @PreFilter & @PostFilter: 对方法传入的数据进行过滤 & 对方法返回的数据进行过滤
    *   filterTarget: String(@PreFilter 使用) - 当接收多个集合时，可以指定对哪一个集合进行过滤
    *   value: String
    *       - filterObject:内置对象表示返回(输入)的集合内的对象
    * */
    @GetMapping("/getAll")
    @PostFilter("filterObject.username.equals('巴御前')")
    public List<User> getAll(){
        return new ArrayList<>(
                Arrays.asList(
                        new User(11,"阿巴巴", "1123456"),
                        new User(17,"巴御前", "20210321")
                )
        );
    }
}
