package com.example.kakao.user;

import com.example.kakao._core.security.CustomUserDetails;
import com.example.kakao._core.security.JwtTokenProvider;
import com.example.kakao._core.security.oauth.*;
import com.example.kakao._core.utils.ApiUtils;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;

import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.io.IOException;
import java.util.Map;

@RequiredArgsConstructor
@RestController
public class UserRestController {

    private final UserService userService;
    private  final CustomOAuthUserService authUserService;

    // (기능1) 회원가입
    @Operation(summary = "회원가입 API", description = "비회원 유저의 회원가입 API이며, email 중복을 체크합니다.")
    @PostMapping("/join")
    public ResponseEntity<?> join(@RequestBody UserRequest request){
        User user = userService.join(request);
        ApiUtils.ApiResult<?> apiResult = ApiUtils.success(user);
        return ResponseEntity.ok(apiResult);
    }

    // (기능2) 로그인
    @Operation(summary = "로그인 API", description = "기존 유저의 로그인 API이며 jwt token을 생성합니다.")
     @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody UserRequest request){
         String jwt =userService.login(request);
         return ResponseEntity.ok().header(JwtTokenProvider.HEADER, jwt).body(ApiUtils.success(null));
     }


    @GetMapping("/login")
    public ModelAndView login(){

        ModelAndView mav = new ModelAndView();
        mav.setViewName("login");

        return mav;
    }


     // (social 로그인)
     @GetMapping("/test/oauth/login")
     public ModelAndView index(@AuthenticationPrincipal CustomOAuthUser principalUser) {// , @AuthenticationPrincipal PrincipalUser principalUser) {

        ModelAndView mav = new ModelAndView();
        mav.setViewName("index");

         if (principalUser != null) {

             String userName = principalUser.getNickName();
             String provider = principalUser.getProvider();
             mav.addObject("user", userName);
             mav.addObject("provider", provider );

         }

         return mav;
     }

     // 회원가입
     @GetMapping("/test/oauth/join")
     public ModelAndView join(Authentication authentication, @AuthenticationPrincipal CustomOAuthUser principalUser) {
         ModelAndView mav = new ModelAndView();
         mav.setViewName("joinPage");

         if (principalUser != null) {
             String userName = principalUser.getNickName();
//             mav.addObject("username", userName);
             String email = principalUser.getEmail();
//             mav.addObject("email", email);

             mav.addObject("UserRequest", new UserRequest(userName, "", email));
         }

         return mav;
     }


    @Operation(summary = "oauth 회원가입 추가정보 update API", description = "oauth 회원의 회원가입 후 추가정보 update")
    @PostMapping("/test/oauth/update")
    public ModelAndView update(@ModelAttribute("UserRequest") UserRequest request, @AuthenticationPrincipal CustomOAuthUser principalUser){
        User user = userService.update(request);
        ApiUtils.ApiResult<?> apiResult = ApiUtils.success(user);
        ModelAndView mav = new ModelAndView();
        mav.setViewName("login");

        return mav;
//        return ResponseEntity.ok(apiResult);
    }


         // 사용 안함 - 프론트 요구사항에 이메일 중복 검사 로직 없음.
    // @PostMapping("/check")

    // (기능3) - 로그아웃
    // 사용 안함 - 프론트에서 localStorage JWT 토큰을 삭제하면 됨.
    // @GetMapping("/logout")

}