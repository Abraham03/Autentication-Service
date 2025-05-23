package com.GestionRemodelacion.gestion.dto.response;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

public class AuthResponse {

    private final String token;
    private final String type = "Bearer";
    private final Long id;
    private final String username;
    private final List<String> authorities;
    private final Date expirationDate;
    private final String refreshToken;
    

    public AuthResponse(String token, Long id, String username, List<String> authorities, Date expirationDate, String refreshToken) {
        this.token = token;
        this.id = id;
        this.username = username;
        this.authorities = authorities;
        this.expirationDate = expirationDate;
        this.refreshToken = refreshToken;
    }



    // Getters
    public String getToken() { return token; }
    public String getType() { return type; }
    public Long getId() { return id; }
    public String getUsername() { return username; }
    public List<String> getAuthorities() { return authorities; }
    public String getExpirationDate() {
        return new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(expirationDate);
    }
    public String getRefreshToken() { return refreshToken; }

}
