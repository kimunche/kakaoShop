package com.example.kakao.user;

import com.example.kakao._core.errors.exception.Exception400;
import com.example.kakao._core.errors.exception.Exception401;
import com.example.kakao._core.errors.exception.Exception500;
import com.example.kakao._core.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@Transactional(readOnly = true)
@RequiredArgsConstructor
@Service
public class UserService {

    private final UserJPARepository userJPARepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public User join(UserRequest request) {
        try{
            if(userJPARepository.existsByEmail(request.getEmail())){
                throw new Exception400("동일한 이메일이 존재합니다 : "+request.getEmail());
            }

            String password = passwordEncoder.encode(request.getPassword());

            List<String> roles = new ArrayList<>();
            roles.add("ROLE_USER");
            User user = request.toUserEntity(password, roles);

            userJPARepository.save(user);
        } catch (Exception e){
            throw new Exception500("failed to join");
        }

        return userJPARepository.findByUsername(request.getUsername())
                .orElseThrow(()-> new Exception500("cannot find user : "+ request.getUsername()));
    }

    @Transactional
    public String login(UserRequest request) {
        User user = userJPARepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new Exception500("cannot find email : "+request.getEmail()));

        if (passwordEncoder.matches(passwordEncoder.encode(request.getPassword()), user.getPassword())) {
            throw new Exception401("wrong email or password");
        }

        String token = JwtTokenProvider.create(user);

        return token;
    }

    @Transactional
    public User update(UserRequest request) {
        try {

            User user = userJPARepository.findByEmail(request.getEmail())
                    .orElseThrow(()-> new Exception500("cannot find user : "+ request.getEmail()));

            String password = passwordEncoder.encode(request.getPassword());

            List<String> roles = new ArrayList<>();
            roles.add("ROLE_USER");

            user.updateInfo(password, request.getUsername(), roles);

            userJPARepository.save(user);
        } catch (Exception e) {
            throw new Exception500("failed to update");
        }
        return userJPARepository.findByUsername(request.getUsername())
                .orElseThrow(()-> new Exception500("cannot find user : "+ request.getUsername()));
    }
}
