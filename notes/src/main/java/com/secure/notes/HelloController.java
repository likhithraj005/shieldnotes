package com.secure.notes;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {
    @GetMapping("/hello")
    public String HelloWorld(){
        return "hello world";
    }

    @GetMapping("/")
    public String Hi(){
        return "hi";
    }

    @GetMapping("/contact")
    public String contact(){
        return "contact";
    }
}
