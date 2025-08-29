package com.pdfsigner.pdf_signer;

import java.security.SecureRandom;
import java.util.*;

public class MapDemo {
    public static void main(String[] args) {
        Map<String, Object> variables = new HashMap<>();

        // variables.put("username", "Ameth"); // String
        // variables.put("age", 30); // Integer
        // variables.put("isVerified", true); // Boolean
        // variables.put("pi", 3.14); // Double
        // variables.put("list", List.of("A", "B", "C")); // List<String>

        // // Loop through all entries
        // for (Map.Entry<String, Object> entry : variables.entrySet()) {
        // Object value = entry.getValue();

        // System.out.println("-------------------------------");
        // System.out.println(
        // "The key: " + entry.getKey() + " = The value: " + value + " | runtime type =
        // "
        // + value.getClass());
        // }

        SecureRandom random = new SecureRandom();
        String MyString = "ThebestBasketballPlayer";
        StringBuilder sb = new StringBuilder(MyString.length());

        for (int i = 0; i < MyString.length() + 24; i++) {
            sb.append(MyString.charAt(random.nextInt(MyString.length())));
        }

        String token = sb.toString();
        System.out.println("Generated token: " + token);

    }

}
