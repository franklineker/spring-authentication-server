package com.frank.authorization_server.web.controller;

import com.frank.authorization_server.service.UserService;
import com.frank.authorization_server.web.dto.UserDTO;
import lombok.AllArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@AllArgsConstructor
@RequestMapping("/auth/user")
@CrossOrigin("*")
public class UserController {

    private final UserService userService;

    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<UserDTO> createUser(@RequestBody UserDTO dto){
        UserDTO createdUser = userService.createUser(dto);
        return ResponseEntity.ok(createdUser);
    }
}
