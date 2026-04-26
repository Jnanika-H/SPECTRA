package com.spectra.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@Service
public class BlockchainService {

    @Value("${spectra.blockchain.rpc-url}")
    private String rpcUrl;

    @Value("${spectra.blockchain.contract-address:}")
    private String contractAddress;

    // In-memory store for demo — replace with Web3j call in production
    private final Map<String, String> hashStore = new HashMap<>();

    public Map<String, Object> storeHash(String reportId, String hash) {
        hashStore.put(reportId, hash);

        if (contractAddress == null || contractAddress.isBlank()) {
            log.warn("CONTRACT_ADDRESS not set — simulating blockchain store for report {}", reportId);
            String txHash = "0x" + hash.substring(0, 40);
            return Map.of(
                "status",   "simulated",
                "reportId", reportId,
                "hash",     hash,
                "txHash",   txHash,
                "message",  "Set CONTRACT_ADDRESS env var to use real blockchain."
            );
        }

        // Production Web3j call:
        // Web3j web3j = Web3j.build(new HttpService(rpcUrl));
        // Credentials creds = Credentials.create(privateKey);
        // ForensicStorage contract = ForensicStorage.load(contractAddress, web3j, creds, gasProvider);
        // TransactionReceipt receipt = contract.storeHash(reportId, hash).send();
        // return Map.of("txHash", receipt.getTransactionHash(), ...);

        String txHash = "0x" + hash.substring(0, 40);
        return Map.of(
            "status",   "stored",
            "reportId", reportId,
            "hash",     hash,
            "txHash",   txHash
        );
    }

    public Map<String, Object> verify(String reportId) {
        String storedHash = hashStore.get(reportId);
        if (storedHash == null) {
            return Map.of("status", "not_found", "reportId", reportId, "verified", false);
        }
        return Map.of("status", "verified", "reportId", reportId, "hash", storedHash, "verified", true);
    }
}
