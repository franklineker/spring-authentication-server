package com.frank.authorization_server.web.controller;

import com.frank.authorization_server.entity.User;
import com.frank.authorization_server.mapper.UserMapper;
import com.frank.authorization_server.service.UserService;
import com.frank.authorization_server.web.dto.UserRequest;
import com.frank.authorization_server.web.dto.UserResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/auth/user")
public class UserController {

    @Autowired
    private UserService userService;
    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(value = HttpStatus.CREATED)
    public UserResponse createUser(@RequestBody UserRequest request) {
        return UserMapper.toUserResponse(userService.save(request));
    }

    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.OK)
    public List<UserResponse> getUsers() {
        List<User> users = userService.findAll();
        List<UserResponse> response = users.stream()
                .map(user -> UserMapper.toUserResponse(user))
                .collect(Collectors.toList());

        return response;
    }
}
