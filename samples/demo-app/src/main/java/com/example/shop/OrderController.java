package com.example.shop;

import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OrderController {
    private static final Logger log = LoggerFactory.getLogger(OrderController.class);

    @GetMapping("/orders/{id}")
    public Map<String, String> order(@PathVariable String id,
                                     @RequestHeader(value = "User-Agent", defaultValue = "-") String userAgent) {
        log.info("order lookup id={} ua={}", id, userAgent);
        return Map.of("id", id, "status", "SHIPPED");
    }
}
