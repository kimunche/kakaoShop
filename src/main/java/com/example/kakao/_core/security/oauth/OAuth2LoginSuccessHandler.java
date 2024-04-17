package com.example.kakao._core.security.oauth;

import com.example.kakao._core.security.CustomUserDetails;
import com.example.kakao._core.security.JwtTokenProvider;
import com.example.kakao.user.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.transaction.Transactional;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    @Transactional
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        log.info("OAuth2 Login 성공!");

        CustomOAuthUser oAuth2User = (CustomOAuthUser) authentication.getPrincipal();

        // 최초 로그인 = ROLE_GUEST
        if(oAuth2User.getRole().equals("ROLE_GUEST")){
            List<String> roles = new ArrayList<>();
            roles.add("ROLE_GUEST");

            User user = User.builder()
                    .email(oAuth2User.getEmail())
                    .username(oAuth2User.getName())
                    .roles(roles)
                    .build();

            String token = JwtTokenProvider.create(user);
            response.addHeader(JwtTokenProvider.HEADER, token); //accesstoken only!
            request.getRequestDispatcher("/test/oauth/join").forward(request, response);
        }
        else{
            loginSuccess(request, response, oAuth2User);
        }

    }

    private void loginSuccess(HttpServletRequest request, HttpServletResponse response, CustomOAuthUser oAuth2User) throws ServletException, IOException {

        List<String> roles = new ArrayList<>();
        roles.add(oAuth2User.getRole()); //ROLE_USER

        User user = User.builder()
                .email(oAuth2User.getEmail())
                .username(oAuth2User.getName())
                .roles(roles)
                .build();

        String accessToken = JwtTokenProvider.create(user);
        String refreshToken = JwtTokenProvider.createRefreshToken(user);

        response.addHeader(JwtTokenProvider.HEADER, accessToken);
//        response.addHeader(JwtTokenProvider.HEADER, refreshToken);

        ResponseCookie cookie = ResponseCookie.from("refresh-token", refreshToken)
                .httpOnly(true)
                .secure(true)
                .path("/")      // path
                .maxAge(JwtTokenProvider.REFRESH_EXP)
                .sameSite("None")  // sameSite
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
        request.getRequestDispatcher("/test/oauth/login").forward(request, response);
    }
}
