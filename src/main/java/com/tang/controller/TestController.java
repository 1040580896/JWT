package com.tang.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

/**
 * @program: springbootjwt
 * @description:
 * @author: xiaokaixin
 * @create: 2021-10-08 16:31
 **/

@RestController
public class TestController {

    @GetMapping("/test/test")
    public String test(String username, HttpServletRequest request){
        //认证成功后放入session
        request.getSession().setAttribute("username",username);
        return "login ok..";
    }
}
