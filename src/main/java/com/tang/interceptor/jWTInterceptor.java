package com.tang.interceptor;

import com.auth0.jwt.exceptions.AlgorithmMismatchException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tang.utils.JWTUtils;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

/**
 * @program: springbootjwt
 * @description:
 * @author: xiaokaixin
 * @create: 2021-10-11 12:45
 **/
public class jWTInterceptor implements HandlerInterceptor {

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        Map<String ,Object> map = new HashMap<>();

        //获取请求头令牌
        String token = request.getHeader("token");
        try {
            JWTUtils.verify(token);//验证令牌
            return true;    //放行请求
        } catch (TokenExpiredException e) {
            map.put("state", false);
            map.put("msg", "Token已经过期!!!");
        } catch (SignatureVerificationException e){
            map.put("state", false);
            map.put("msg", "签名错误!!!");
        } catch (AlgorithmMismatchException e){
            map.put("state", false);
            map.put("msg", "加密算法不匹配!!!");
        } catch (Exception e) {
            e.printStackTrace();
            map.put("state", false);
            map.put("msg", "无效token~~");
        }
        map.put("state",false);
        //将map转为JSON  jackjson
        String json = new ObjectMapper().writeValueAsString(map);
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().println(json);

        return false;
    }
}
