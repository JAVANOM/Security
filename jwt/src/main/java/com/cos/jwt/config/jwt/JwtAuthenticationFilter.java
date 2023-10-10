package com.cos.jwt.config.jwt;

import java.io.IOException;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;

// 스프링시큐리티에서 UsernamePasswordAuthenticationFilter 가 있음
// /login 요청해서 Username, password 전송하면 (post)
// UsernamePasswordAuthenticationFilter 동작
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter{
    
	private final AuthenticationManager authenticationManager;
	
	
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		
	    System.out.println("JwtAuthenticationFilter : 로그인 시도중");
	    
	    // 1. username, password
	    
	    try {
	    	ObjectMapper om = new ObjectMapper();
	    	User user = om.readValue(request.getInputStream(), User.class);
	    	UsernamePasswordAuthenticationToken authenticationToken = 
	    			new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
	    	
	    	//PrincipalDetailsService의 loadUsername()함수가 실행된 후 정상이면 authentication이 리턴 
	    	//DB에 있는 username과 password가 일치 한다.
	    	Authentication authentication = 
	    			authenticationManager.authenticate(authenticationToken);
	    	
	    	//  로그인이 되었다는 뜻
	    	PrincipalDetails principalDetails = (PrincipalDetails)authentication.getPrincipal();
	    	System.out.println(principalDetails.getUser().getUsername()); //로그인 정상적으로 되었다는 뜻. 
	    	
	    	//authentication 객체가 session영역에 저장을 해야하고 그방이 return 해주면 됨.
	    	//리턴의 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고 하는거임
	    	//굳이 JWT토큰을 사용하면서 세션을 만들 이유가 없음. 근데 단지 권한 처리때문에 SESSION 넣어 줌
	    	
	    	
	    	
	    	return authentication;
			//System.out.println(request.getInputStream().toString());
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		// 오류 시 null 반환
		return null;
	}
	
	// attmptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행
	// JWT 토큰을 만들어서 request 요청한 사용자에게 JWT토큰을 해주면됨
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		System.out.println("인증이 완료");
		PrincipalDetails principalDetails = (PrincipalDetails)authResult.getPrincipal();
		
		// RSA방식 X , HASH 암호 방식
		String jwtToken = JWT.create()
				.withSubject("cos토큰")
				.withExpiresAt(new Date(System.currentTimeMillis()+(60000*10))) //만료시간
				.withClaim("id", principalDetails.getUser().getId())
				.withClaim("username", principalDetails.getUser().getUsername())
				.sign(Algorithm.HMAC512("cos"));
		
		response.addHeader("Authorization", "Bearer"+jwtToken);
	}
}
