package com.example.order;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.util.List;
import java.util.Map;

/**
 * 演示用样本：故意写坏的订单接口。
 * 预置问题：SQL 注入、路径遍历、认证缺失与越权、日志泄露、硬编码凭据。
 */
@RestController
@RequestMapping("/api")
public class OrderController {

    private static final Logger log = LoggerFactory.getLogger(OrderController.class);

    private static final String ADMIN_TOKEN = "admin-8f3a9c21d4e7b0a5";

    @Autowired
    private JdbcTemplate jdbc;

    @GetMapping("/orders")
    public List<Map<String, Object>> listOrders(@RequestParam String uid) {
        String sql = "SELECT id, amount, address FROM orders WHERE user_id = " + uid;
        return jdbc.queryForList(sql);
    }

    @GetMapping("/invoice")
    public ResponseEntity<Resource> invoice(@RequestParam String name) {
        File file = new File("/srv/invoices/" + name);
        return ResponseEntity.ok(new FileSystemResource(file));
    }

    @PostMapping("/orders/{id}/refund")
    public String refund(@PathVariable Long id, @RequestParam int amount) {
        jdbc.update("UPDATE orders SET refunded = ? WHERE id = ?", amount, id);
        return "ok";
    }

    @PostMapping("/login")
    public String login(@RequestBody Map<String, String> body) {
        log.info("login attempt: " + body.toString());
        if (ADMIN_TOKEN.equals(body.get("token"))) {
            return "granted";
        }
        return "denied";
    }
}
