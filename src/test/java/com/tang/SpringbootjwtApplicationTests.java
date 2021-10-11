package com.tang;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Calendar;
import java.util.HashMap;

// @SpringBootTest
class SpringbootjwtApplicationTests {

	@Test
	void contextLoads() {

		HashMap<String, Object> map = new HashMap<>();

		Calendar instance = Calendar.getInstance();
		instance.add(Calendar.SECOND,300);
		String token = JWT.create()
				//.withHeader(map)//header
				.withClaim("userId", 21)//payload
				.withClaim("username", "xiaokaixin")
				.withExpiresAt(instance.getTime())//知道令牌过期时间
				.sign(Algorithm.HMAC256("as%has"));// 签名

		System.out.println(token);

	}

	@Test
	public void test(){
		//创建验证对象
		JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC256("as%has")).build();

		DecodedJWT verify = jwtVerifier.verify("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2MzM3NTczMzEsInVzZXJJZCI6MjEsInVzZXJuYW1lIjoieGlhb2thaXhpbiJ9.PVj08ZtccE1vxNJLhbwcuE1YBFBbEGUIlvqR0eBTcvU");

		//获取荷载中的信息
		System.out.println(verify.getClaim("userId").asInt());
		System.out.println(verify.getClaim("username").asString());

		//获取过期时间
		System.out.println(verify.getExpiresAt());
	}

}
