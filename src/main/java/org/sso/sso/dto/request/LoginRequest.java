package org.sso.sso.dto.request;

import lombok.Data;

@Data
public class LoginRequest {
    private String iin;
    private String password;
}

