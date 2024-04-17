package com.example.kakao.user;

import java.util.List;
import javax.validation.constraints.NotBlank;

import lombok.*;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;
import java.util.Collections;

@Getter
@Setter
public class UserRequest {

    @NotBlank
    private String username;

    @NotBlank
    @Pattern(regexp = "^[\\w._%+-]+@[\\w.-]+\\.[a-zA-Z]{2,6}$", message = "이메일 형식으로 작성해주세요.")
    private String email;

    @NotBlank
    @Size(min = 8, max = 20, message = "8에서 20자 이내여야 합니다.")
    @Pattern(regexp = "^(?=.*[a-zA-Z])(?=.*\\d)(?=.*[@#$%^&+=!~`<>,./?;:'\"\\[\\]{}\\\\()|_-])\\S*$", message = "영문, 숫자, 특수문자가 포함되어야하고 공백이 포함될 수 없습니다.")
    private String password;

    public User toUserEntity(String password, List<String> roles){
        return User.builder()
                .username(username)
                .email(email)
                .roles(roles)
                .password(password)
                .build();
    }

    public UserRequest(String username, String password, String email){
        this.username = username;
        this.password = password;
        this.email = email;
    }


}
