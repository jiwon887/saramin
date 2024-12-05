package com.example.demo.controller;


import com.example.demo.entity.UserEntity;
import com.example.demo.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    AuthService authService;

    // 회원가입
    @PostMapping("/register")
    public UserEntity register(@RequestParam String email,
                               @RequestParam String password,
                               @RequestParam String name,
                               @RequestParam String phone) {

        authService.registerUser(email, password, name, phone);

        return "register";
    }

    // 로그인
    @PostMapping("/login")
    public String login(@RequestParam String email,
                        @RequestParam String password){
        return authService.loginUser(email, password);
    }

    // 회원 정보 수정
    @PutMapping("/profile")
    public UserEntity updateProfile(@RequestParam String email,
                                    @RequestParam(required = false) String name,
                                    @RequestParam(required = false) String phone,
                                    @RequestParam(required = false) String password) {
        return authService.updateProfile(email, name, phone, password);
    }

    // 토큰 갱신
    @PostMapping("/refresh")
    public String refreshToken(@RequestParam String refreshToken) {
        return authService.refreshToken(refreshToken);
    }


}
