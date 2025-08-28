package com.frank.authorization_server.web.controller;

import com.frank.authorization_server.config.AppConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
@CrossOrigin("*")
public class LoginController {
    @Autowired
    private AppConfig appConfig;
    @GetMapping("/login")
    public String login(Model model) {
        model.addAttribute("reactAppUri", appConfig.getUris().getReactAppUri());
        return "login";
    }

    @GetMapping("/logout")
    String logout() {
        return "logout";
    }

    @PostMapping("/logout")
    public String logoutOK(HttpSecurity http) throws Exception {
        http.logout(logout -> logout
                .deleteCookies("JSESSIONID")
                .invalidateHttpSession(true)
                .clearAuthentication(true)
        );

        return "login?logout";
    }
}
