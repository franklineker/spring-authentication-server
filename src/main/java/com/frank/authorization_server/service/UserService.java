package com.frank.authorization_server.service;

import com.frank.authorization_server.entity.User;
import com.frank.authorization_server.exeptions.UserAlreadyExistsException;
import com.frank.authorization_server.mapper.UserMapper;
import com.frank.authorization_server.repository.UserRepository;
import com.frank.authorization_server.web.dto.UserRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Service
@Slf4j
public class UserService {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;

    public User save(UserRequest userReq) {

        boolean isEmailPresent = Optional.ofNullable(userRepository.findByUsername(userReq.getUsername())).isPresent();

        System.out.println("email present: " + isEmailPresent);

        if (isEmailPresent){
            throw new UserAlreadyExistsException("Email already taken: " + userReq.getUsername(), "email");
        }

        User user = UserMapper.toUser(userReq);
        user.setPassword(passwordEncoder.encode(userReq.getPassword()));
        user.setCreatedAt(LocalDateTime.now());

        return  userRepository.save(user);
    }

    public List<User> findAll() {
        return userRepository.findAll();
    }

}
