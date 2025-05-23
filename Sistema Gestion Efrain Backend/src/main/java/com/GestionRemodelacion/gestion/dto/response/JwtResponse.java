package com.GestionRemodelacion.gestion.dto.response;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

public class JwtResponse {

    private String accessToken;
    private String type = "Bearer";
    private Long userId ;
    private String username;
    private List<String> autorities;
    private Date expirationDate;

    // Constructor principal
    public JwtResponse(String accessToken, Long userId , String username, List<String> roles, Date expirationDate) {
        this.accessToken = accessToken;
        this.userId  = userId ;
        this.username = username;
        this.autorities = roles;
        this.expirationDate = expirationDate;
    }
    public JwtResponse(String token) {
        this.accessToken = token;
    }

    public String getToken() {
        return accessToken;
    }

    public void setToken(String token) {
        this.accessToken = token;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public Long getId() {
        return userId ;
    }

    public void setId(Long id) {
        this.userId  = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public List<String> getRoles() {
        return autorities;
    }

    public void setRoles(List<String> roles) {
        this.autorities = roles;
    }

    public String getExpirationDate() {
        return new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(expirationDate);
    }
    



}
