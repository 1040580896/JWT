package com.tang.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;

/**
 * @program: springbootjwt
 * @description:
 * @author: xiaokaixin
 * @create: 2021-10-09 21:26
 **/
public class JWTUtils {

    private static final String SIGN = "as%has";

    /**
     * 生成token  header.payload.sign
     */
    public static String getToken(Map<String,String> map){

        Calendar instance = Calendar.getInstance();
        instance.add(Calendar.DATE,7);//默认7天过期

        //创建jwt builder
        JWTCreator.Builder builder = JWT.create();

        //payload
        map.forEach((k,v)->{
            builder.withClaim(k,v);
        });

        //sign
        String token = builder.withExpiresAt(instance.getTime())//指定令牌过期时间
                .sign(Algorithm.HMAC256(SIGN));

        return token;
    }

    /**
     * 验证token合法性
     */

    public static void verify(String token){
        JWT.require(Algorithm.HMAC256(SIGN)).build().verify(token);
    }

    /**
     * 获取token信息方法
     */

    public static DecodedJWT getTokenInfo(String token){
        DecodedJWT verify = JWT.require(Algorithm.HMAC256(SIGN)).build().verify(token);
        return verify;
    }
}
