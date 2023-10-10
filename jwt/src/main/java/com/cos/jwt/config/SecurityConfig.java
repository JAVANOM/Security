package com.cos.jwt.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;

import com.cos.jwt.config.jwt.JwtAuthenticationFilter;
import com.cos.jwt.config.jwt.JwtAutorizationFilter;
import com.cos.jwt.filter.MyFilter1;
import com.cos.jwt.repository.UserRepository;

@Configuration
@EnableWebSecurity //시큐리티 활성화 -> 기본 스프링 필터 체인에 등록
public class SecurityConfig {
    
	
	@Autowired
	private UserRepository userRepository;
	
	@Autowired
	private CorsConfig corsConfig;
	
	@Bean
	SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		return http
				//.addFilterBefore(new MyFilter1(), BasicAuthenticationFilter.class) // BasicAuthenticationFilter 시작 전에 필터가 실행
				.csrf().disable()
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) //세션사용 x
				.and()
				.formLogin().disable()
				.httpBasic().disable() // 기본인증 방식
				.authorizeRequests(authroize -> authroize.antMatchers("/api/v1/user/**")
						.access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
						.antMatchers("/api/v1/manager/**")
						.access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
						.antMatchers("/api/v1/admin/**")
						.access("hasRole('ROLE_ADMIN')")
						.anyRequest().permitAll())
				.build();
	}
	
	
	public class MyCustomDs1 extends AbstractHttpConfigurer<MyCustomDs1, HttpSecurity>{
		
		@Override
		public void configure(HttpSecurity http) throws Exception {
			
			AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
			http
			     .addFilter(corsConfig.corsFilter())
			     .addFilter(new JwtAuthenticationFilter(authenticationManager))
			     .addFilter(new JwtAutorizationFilter(authenticationManager, userRepository));
			
			
			
		}
	}
	

}
