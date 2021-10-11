package com.tang.controller;

import com.auth0.jwt.exceptions.AlgorithmMismatchException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.tang.entity.User;
import com.tang.service.UserService;
import com.tang.utils.JWTUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

/**
 * @program: springbootjwt
 * @description:
 * @author: xiaokaixin
 * @create: 2021-10-11 10:34
 **/

@RestController
@Slf4j
public class UserController {

    @Autowired
    private UserService userService;

    @GetMapping("/user/login")
    public Map<String ,Object> login(User user){
        log.info("用户名：{}",user.getName());
        log.info("密码：{}",user.getPassword());

        Map<String ,Object> map = new HashMap<>();
        try {
            User userDB = userService.login(user);
            Map<String,String> payload = new HashMap<>();
            payload.put("id",userDB.getId());
            payload.put("name",userDB.getName());
            //生成JWT令牌
            String token = JWTUtils.getToken(payload);

            map.put("state",true);
            map.put("msg","认证成功");
            map.put("token",token);

        }catch (Exception e){
            map.put("state",false);
            map.put("msg",e.getMessage());
        }
        return map;
    }

    // @PostMapping("/user/test")
    // public Map<String ,Object> test(String token){
    //     log.info("当前token为:{}",token);
    //     Map<String, Object> map = new HashMap<>();
    //     try {
    //         JWTUtils.verify(token);//验证令牌
    //         map.put("msg", "验证通过~~~");
    //         map.put("state", true);
    //     } catch (TokenExpiredException e) {
    //         map.put("state", false);
    //         map.put("msg", "Token已经过期!!!");
    //     } catch (SignatureVerificationException e){
    //         map.put("state", false);
    //         map.put("msg", "签名错误!!!");
    //     } catch (AlgorithmMismatchException e){
    //         map.put("state", false);
    //         map.put("msg", "加密算法不匹配!!!");
    //     } catch (Exception e) {
    //         e.printStackTrace();
    //         map.put("state", false);
    //         map.put("msg", "无效token~~");
    //     }
    //     return map;
    //
    // }

    @PostMapping("/user/test")
    public Map<String ,Object> test(HttpServletRequest request){
        //
        Map<String, Object> map = new HashMap<>();
        //处理业务逻辑
        String token = request.getHeader("token");
        DecodedJWT verify = JWTUtils.getTokenInfo(token);
        //获取信息
        String name = verify.getClaim("name").asString();
        log.info("用户名字：{}",name);
        map.put("msg", "验证通过~~~");
        map.put("state", true);
        return map;

    }
}
