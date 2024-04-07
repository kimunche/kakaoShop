package com.example.kakao._core.security.oauth;

import com.example.kakao._core.security.CustomUserDetails;
import com.example.kakao._core.security.JwtTokenProvider;
import com.example.kakao.user.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        log.info("OAuth2 Login 성공!");

        CustomOAuthUser oAuth2User = (CustomOAuthUser) authentication.getPrincipal();

        List<String> roles = new ArrayList<>();
        roles.add("ROLE_USER");

        User user = User.builder()
                .email(oAuth2User.getEmail())
                .username(oAuth2User.getName())
                .roles(roles)
                .build();

        String token = JwtTokenProvider.create(user);
        response.addHeader(JwtTokenProvider.HEADER, token);
        request.getRequestDispatcher("/test/oauth/kakao").forward(request, response);

        //refreshtoken??

//        loginSuccess(response, user);
    }

    private void loginSuccess(HttpServletResponse response, User user) {

        String token = JwtTokenProvider.create(user);
        response.addHeader(JwtTokenProvider.HEADER, token);
    }
}
