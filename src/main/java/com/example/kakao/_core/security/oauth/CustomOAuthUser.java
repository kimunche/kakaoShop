package com.example.kakao._core.security.oauth;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;


import java.util.Collection;
import java.util.Map;

@Getter
public class CustomOAuthUser extends DefaultOAuth2User {
    private String email;
    private String role;
    private String nickName;
    private String provider;

    public CustomOAuthUser(Collection<? extends GrantedAuthority> authorities
            , Map<String, Object> attributes
            , String nameAttributeKey
            , String email
            , String role, String nickName, String provider) {
        super(authorities, attributes, nameAttributeKey);
        this.email = email;
        this.role = role;
        this.nickName = nickName;
        this.provider = provider;
    }
}
