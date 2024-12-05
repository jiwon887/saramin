package com.example.demo.service;


import com.example.demo.JwtUtil;
import com.example.demo.entity.UserEntity;
import com.example.demo.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AuthService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JwtUtil jwtUtil;

    PasswordEncoder passwordEncoder;


    // 유저 찾기
    public Optional<UserEntity> getUserByEmail(String email){
        return userRepository.findByEmail(email);
    }

    // 회원가입 서비스
    public UserEntity registerUser(String email, String password, String name, String phone){
        if (userRepository.findByEmail(email).isPresent()){
            throw new RuntimeException(" 존재하는 이메일입니다. ");
        }
        UserEntity user = UserEntity.builder()
                .email(email)
                .password(password)
                .name(name)
                .phone(phone)
                .build();
        return userRepository.save(user);
    }

    // 로그인 서비스
    public String loginUser(String email, String password){
        Optional<UserEntity> userOpt = userRepository.findByEmail(email);

        if (userOpt.isPresent()){
            UserEntity user = userOpt.get();

            if (passwordEncoder.matches(password, user.getPassword())){
                return jwtUtil.generateToken(user.getEmail());
            }else {
                throw new RuntimeException("비밀번호 오류");
            }
        }
        else {
            throw new RuntimeException("등록되지 않은 사용자");
        }
    }


    // 회원 정보 수정
    public UserEntity updateProfile(String email, String newPassword, String newName, String newPhone){
        Optional<UserEntity> userOpt = userRepository.findByEmail(email);

        if(userOpt.isPresent()){

            UserEntity user = userOpt.get();

            UserEntity newUser = user.toBuilder()
                    .name(newName !=null ? newName : user.getName())
                    .phone(newPhone !=null ? newPhone : user.getPhone())
                    .password(newPassword !=null ? newPassword: passwordEncoder.encode(newPassword))
                    .build();

            return userRepository.save(newUser);
        } else{
            throw new RuntimeException("사용자를 찾을 수 없음");
        }

    }


    // 토큰 재발급
    public String refreshToken(String refreshToken) {
        // Refresh Token 검증
        if (jwtUtil.validateToken(refreshToken)) {
            // 새로운 Access Token 발급
            return jwtUtil.generateRefreshToken(refreshToken);
        } else {
            throw new RuntimeException("유효하지 않은 Token");
        }
    }



}
