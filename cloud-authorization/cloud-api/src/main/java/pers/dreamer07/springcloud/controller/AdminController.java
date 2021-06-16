package pers.dreamer07.springcloud.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @program: cloud-authorization
 * @description: 测试接口，用户登录用户信息
 * @author: EMTKnight
 * @create: 2021-06-09
 **/
@RestController
@RequestMapping("/admin")
public class AdminController {

    @GetMapping("/getCurrentAdminInfo")
    @PreAuthorize("hasAnyAuthority('admin')")
    public Object getCurrentAdminInfo(Authentication authentication){
        return authentication;
    }

}
