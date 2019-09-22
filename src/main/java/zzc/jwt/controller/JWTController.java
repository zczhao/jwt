package zzc.jwt.controller;

import java.util.UUID;

import javax.servlet.http.HttpServletRequest;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import io.jsonwebtoken.Claims;
import zzc.jwt.commons.JWTResponseData;
import zzc.jwt.commons.JWTResult;
import zzc.jwt.commons.JWTSubject;
import zzc.jwt.commons.JWTUsers;
import zzc.jwt.commons.JWTUtils;

@Controller
public class JWTController {

	@RequestMapping("/testAll")
	@ResponseBody
	public Object testAll(HttpServletRequest request) {
		String token = request.getHeader("Authorization");
		JWTResult result = JWTUtils.validateJWT(token);
		JWTResponseData responseData = new JWTResponseData();
		if (result.isSuccess()) {
			responseData.setCode(200);
			Claims claims = result.getClaims();
			responseData.setData(claims.getSubject());
			// 重新成功新的token，就是为了重置token的有效期
			String newToken = JWTUtils.createJWT(claims.getId(), claims.getIssuer(), claims.getSubject(),
					1 * 60 * 1000);
			responseData.setToken(newToken);
			return responseData;
		} else {
			responseData.setCode(500);
			responseData.setMsg("用户未登录");
			return responseData;
		}
	}

	@RequestMapping("/login")
	@ResponseBody
	public Object login(String username, String password) {
		JWTResponseData responseData = null;
		// 认证用户信息，本案例中访问静态数据。
		if (JWTUsers.isLogin(username, password)) {
			JWTSubject subject = new JWTSubject(username);
			String jwtToken = JWTUtils.createJWT(UUID.randomUUID().toString(), "sxt-test-jwt",
					JWTUtils.generalSubject(subject), 1 * 60 * 1000);
			responseData = new JWTResponseData();
			responseData.setCode(200);
			responseData.setData(null);
			responseData.setMsg("登录成功");
			responseData.setToken(jwtToken);
		} else {
			responseData = new JWTResponseData();
			responseData.setCode(500);
			responseData.setData(null);
			responseData.setMsg("登录失败");
			responseData.setToken(null);
		}
		return responseData;
	}

}
