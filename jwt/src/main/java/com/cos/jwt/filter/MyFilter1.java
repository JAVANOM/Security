package com.cos.jwt.filter;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class MyFilter1 implements Filter{

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		
		HttpServletRequest req = (HttpServletRequest) request;
		HttpServletResponse res = (HttpServletResponse) response;
		
		//토큰 : cos
		if(req.getMethod().equals("POST")) {
		    System.out.println("POST 요청");
			String headerAuth = req.getHeader("Authorization");
	 	    System.out.println(headerAuth);
	 	    System.out.println("필터1");
	 	    
	 	    if(headerAuth.equals("cos")) {
	 	    	chain.doFilter(req, res);
	 	    	
	 	    }else {
	 	    	PrintWriter out = res.getWriter();
	 	    	out.print("인증x");
	 	    }
		}
		
		
	}

}
