package com.example.kakao._core.security.oauth;

import com.example.kakao._core.security.oauth.CustomOAuthUser;
import com.example.kakao._core.security.oauth.OAuthAttributes;
import com.example.kakao.user.User;
import com.example.kakao.user.UserJPARepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomOAuthUserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {
    private final UserJPARepository userJPARepository;

    private static final String KAKAO = "kakao";
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        log.info("CustomOAuth2UserService.loadUser() 실행 - OAuth2 로그인 요청 진입");

        OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate = new DefaultOAuth2UserService();
        OAuth2User oAuth2User = delegate.loadUser(userRequest); //userRequest를 통해서 OAuth서비스에서 가져온 유저정보를 담고 있는 oAuth2User를 가져온다.

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        String socialType = getSocialType(registrationId);
        String userNameAttributeName = userRequest.getClientRegistration()
                .getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName(); // OAuth2 로그인 시 키(PK)가 되는 값

        Map<String, Object> attributes = oAuth2User.getAttributes();// 소셜 로그인에서 API가 제공하는 userInfo의 Json 값(유저 정보들)

        OAuthAttributes extractAttributes = OAuthAttributes.of(socialType, userNameAttributeName, attributes);

        User createdUser = getUser(extractAttributes);

        return new CustomOAuthUser(
                Collections.singleton(new SimpleGrantedAuthority(createdUser.getRoles().get(0))),
                attributes,
                extractAttributes.getNameAttributeKey(),
                createdUser.getEmail(),
                createdUser.getRoles().get(0),
                createdUser.getUsername(),
                socialType
        );
    }

    private String getSocialType(String registrationId) {
        if(KAKAO.equals(registrationId)){
            return KAKAO;
        }
        return "";
    }

    private User getUser(OAuthAttributes attributes) {
        User findUser = userJPARepository.findByUsername(attributes.getOAuth2UserInfo().getNickname()).orElse(null);

        if(findUser == null) {
            return saveUser(attributes);
        }
        return findUser;
    }

    private User saveUser(OAuthAttributes attributes){
        User newUser = attributes.toEntity(attributes.getOAuth2UserInfo());

        return userJPARepository.save(newUser);
    }
}
