package com.colak.springtutorial.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/public")
public class PublicController {

    // This URL can be accessed by everybody
    // http://localhost:8080/public/greetPublic
    @GetMapping("/greetPublic")
    public String greetPublic() {
        return "Hello Public";
    }

}