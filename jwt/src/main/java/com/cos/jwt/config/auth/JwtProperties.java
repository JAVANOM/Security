package com.cos.jwt.config.auth;

public interface JwtProperties {
    String SECRET = "cos";
    int EXPRIRATION = 60000 * 10;
    String TOKEN_PREFIX = "Bearer";
    String HEADER_STRING = "Authorization";
}
