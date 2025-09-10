package com.frank.authorization_server.service;

import com.frank.authorization_server.entity.User;
import com.frank.authorization_server.mapper.UserMapper;
import com.frank.authorization_server.repository.UserRepository;
import com.frank.authorization_server.web.dto.UserDTO;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;


@AllArgsConstructor
@Service
public class UserService {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;

    @Transactional
    public UserDTO createUser(@Valid UserDTO dto){

        String passwordEncoded = passwordEncoder.encode(dto.getPassword());
        dto.setPassword(passwordEncoded);

        User user = userRepository.save(UserMapper.toUser(dto));

        return UserMapper.toUserResponseDTO(user);
    }
}
