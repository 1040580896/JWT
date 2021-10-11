package com.tang.config;

import com.tang.interceptor.jWTInterceptor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * @program: springbootjwt
 * @description:
 * @author: xiaokaixin
 * @create: 2021-10-11 12:51
 **/
@Configuration
public class InterceptorConfig implements WebMvcConfigurer {
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new jWTInterceptor())
                .addPathPatterns("/user/test")      //其他接口token验证
                .excludePathPatterns("/user/login");    //所有用户都放行
    }
}
