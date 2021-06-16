package pers.dreamer07.security.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * @program: spring-security
 * @description: Csrf
 * @author: EMTKnight
 * @create: 2021-03-22
 **/
@Controller
public class CsrfController {

    @GetMapping("/index")
    public String index(){
        return "/index";
    }

    @PostMapping("/hello")
    @ResponseBody
    public String hello(){
        return "hello";
    }

}
