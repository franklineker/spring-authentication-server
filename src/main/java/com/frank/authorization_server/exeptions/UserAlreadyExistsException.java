package com.frank.authorization_server.exeptions;

import lombok.Data;

@Data
public class UserAlreadyExistsException  extends RuntimeException {

    private String reason;
    public UserAlreadyExistsException(String message, String reason) {
        super(message);
        this.reason = reason;
    }
}
