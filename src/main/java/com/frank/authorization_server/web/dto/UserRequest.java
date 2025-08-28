package com.frank.authorization_server.web.dto;

import com.frank.authorization_server.entity.User;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserRequest {

   private String username;
   private String password;
   private List<String> roles;
}
