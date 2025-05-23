package com.GestionRemodelacion.gestion.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class hello {

        @GetMapping("/hello")
    public String helloo() {
        return "¡Hola, mundo!";
    }

}
