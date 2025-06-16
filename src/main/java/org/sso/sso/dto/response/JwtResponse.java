package org.sso.sso.dto.response;

import lombok.Data;

@Data
public class JwtResponse {
    private String access;
    private String refresh;
    private String iin;
    private String role;
}
