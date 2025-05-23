package com.GestionRemodelacion.gestion.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Clase de configuración para las propiedades relacionadas con JWT.
 * Las propiedades se cargan desde application.yml con el prefijo "jwt"
 */
@Configuration
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {

    private String secretKey;
    private long expirationMs;
    private String issuer;
    private String header;
    private String prefix;
    private long refreshExpirationMs;
     private long blacklistCleanupInterval = 3600000; // Valor por defecto

    public long getRefreshExpirationMs() {
        return refreshExpirationMs;
    }

    public void setRefreshExpirationMs(long refreshExpirationMs) {
        this.refreshExpirationMs = refreshExpirationMs;
    }

    public String getSecretKey() {
        return secretKey;
    }

    public void setSecretKey(String secretKey) {
        this.secretKey = secretKey;
    }

    public long getExpirationMs() {
        return expirationMs;
    }

    public void setExpirationMs(long expirationMs) {
        this.expirationMs = expirationMs;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getHeader() {
        return header;
    }

    public void setHeader(String header) {
        this.header = header;
    }

    public String getPrefix() {
        return prefix;
    }

    public void setPrefix(String prefix) {
        this.prefix = prefix;
    }

    public long getBlacklistCleanupInterval() {
        return blacklistCleanupInterval;
    }

    public void setBlacklistCleanupInterval(long blacklistCleanupInterval) {
        this.blacklistCleanupInterval = blacklistCleanupInterval;
    }


}
