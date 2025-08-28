package com.pdfsigner.pdf_signer;

import java.util.*;

public class MapDemo {
    public static void main(String[] args) {
        Map<String, Object> variables = new HashMap<>();

        variables.put("username", "Ameth"); // String
        variables.put("age", 30); // Integer
        variables.put("isVerified", true); // Boolean
        variables.put("pi", 3.14); // Double
        variables.put("list", List.of("A", "B", "C")); // List<String>

        // Loop through all entries
        for (Map.Entry<String, Object> entry : variables.entrySet()) {
            Object value = entry.getValue();

            System.out.println("-------------------------------");
            System.out.println(
                    "The key: " + entry.getKey() + " = The value: " + value + " | runtime type = "
                            + value.getClass());
        }
    }
}
