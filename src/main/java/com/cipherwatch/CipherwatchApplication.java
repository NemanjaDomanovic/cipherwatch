package com.cipherwatch;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class CipherwatchApplication {

    public static void main(String[] args) {
        SpringApplication.run(CipherwatchApplication.class, args);
        System.out.println("╔══════════════════════════════════════════╗");
        System.out.println("║        CipherWatch je pokrenut!          ║");
        System.out.println("║     API: http://localhost:8080           ║");
        System.out.println("╚══════════════════════════════════════════╝");
    }
}