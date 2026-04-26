package com.spectra.controller;

import com.spectra.service.BlockchainService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/blockchain")
@RequiredArgsConstructor
public class BlockchainController {

    private final BlockchainService blockchainService;

    /**
     * POST /api/blockchain
     * Body: { "reportId": "...", "hash": "..." }
     * Stores report hash on Ethereum and returns tx hash.
     */
    @PostMapping
    public ResponseEntity<Map<String, Object>> storeHash(@RequestBody Map<String, String> body) {
        String reportId = body.get("reportId");
        String hash     = body.get("hash");
        Map<String, Object> result = blockchainService.storeHash(reportId, hash);
        return ResponseEntity.ok(result);
    }

    /** GET /api/blockchain/verify/{reportId} */
    @GetMapping("/verify/{reportId}")
    public ResponseEntity<Map<String, Object>> verify(@PathVariable String reportId) {
        Map<String, Object> result = blockchainService.verify(reportId);
        return ResponseEntity.ok(result);
    }
}
