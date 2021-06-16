package pers.dreamer07.security.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @program: spring-security
 * @description: 测试 Csrf
 * @author: EMTKnight
 * @create: 2021-03-22
 **/
@RestController
public class CsrfController {

    @PostMapping("/transfer")
    public void transferMoney(String name, Integer money) {
        System.out.println("name = " + name);
        System.out.println("money = " + money);
    }
    @GetMapping("/hello")
    public String hello() {
        return "hello";
    }

}
