package com.example.kakao._core.security;


import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.kakao.user.StringArrayConverter;
import com.example.kakao.user.User;
import org.springframework.stereotype.Component;

import java.util.Date;


@Component
public class JwtTokenProvider {
    private static final Long EXP = 1000L * 60 * 60 * 48; // 48시간 - 테스트 하기 편함.
    public static Long REFRESH_EXP = 1000L * 3600 * 24 * 365;
    public static final String TOKEN_PREFIX = "Bearer "; // 스페이스 필요함
    public static final String HEADER = "Authorization";
    private static final String SECRET = "MySecretKey";
    private static final String REFRESH_SECRET = "MySecretKeyRefresh";

    public static String create(User user) {
        StringArrayConverter sac = new StringArrayConverter();
        String roles = sac.convertToDatabaseColumn(user.getRoles());
        String jwt = JWT.create()
                .withSubject(user.getEmail())
                .withExpiresAt(new Date(System.currentTimeMillis() + EXP))
                .withClaim("id", user.getId())
                .withClaim("role", roles)
                .sign(Algorithm.HMAC512(SECRET));
        return TOKEN_PREFIX + jwt;
    }

    public static String createRefreshToken(User user) {
        StringArrayConverter sac = new StringArrayConverter();
        String roles = sac.convertToDatabaseColumn(user.getRoles());
        String jwt = JWT.create()
                .withSubject(user.getEmail())
                .withExpiresAt(new Date(System.currentTimeMillis() + REFRESH_EXP))
                .withClaim("id", user.getId())
                .withClaim( "role", roles)
                .sign(Algorithm.HMAC512(REFRESH_SECRET));
        return jwt;
    }


    public static DecodedJWT verify(String jwt) throws SignatureVerificationException, TokenExpiredException {
        DecodedJWT decodedJWT = JWT.require(Algorithm.HMAC512(SECRET))
                .build().verify(jwt);
        return decodedJWT;
    }

    public static DecodedJWT verifyRefreshToken(String jwt) throws SignatureVerificationException, TokenExpiredException {
        return JWT.require(Algorithm.HMAC512(REFRESH_SECRET))
                .build().verify(jwt);
    }

    public static Long getRemainExpiration(String jwt) {
        DecodedJWT decodedJTW = verify(jwt);
        Date now = new Date();
        Date end = decodedJTW.getExpiresAt();
        return end.getTime() - now.getTime();
    }

}
