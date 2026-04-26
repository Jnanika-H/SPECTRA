// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * SPECTRA — ForensicStorage Smart Contract
 * ==========================================
 * Stores SHA-256 hashes of forensic investigation reports on Ethereum.
 * Once stored, hashes are immutable — any tampering of the original
 * report is immediately detectable by comparing against the on-chain hash.
 *
 * Deploy on Ganache (local) or any EVM-compatible network.
 */
contract ForensicStorage {

    // ── Events ────────────────────────────────────────────────────────────────
    event HashStored(
        string  indexed reportId,
        bytes32         hash,
        address         storedBy,
        uint256         timestamp
    );

    event HashVerified(
        string  indexed reportId,
        bool            matched,
        address         verifiedBy,
        uint256         timestamp
    );

    // ── Storage ───────────────────────────────────────────────────────────────
    struct ForensicRecord {
        bytes32 reportHash;
        address storedBy;
        uint256 storedAt;
        bool    exists;
    }

    mapping(string => ForensicRecord) private records;
    string[] private reportIds;

    address public owner;

    // ── Access control ────────────────────────────────────────────────────────
    modifier onlyOwner() {
        require(msg.sender == owner, "ForensicStorage: caller is not owner");
        _;
    }

    modifier reportExists(string memory reportId) {
        require(records[reportId].exists, "ForensicStorage: report not found");
        _;
    }

    modifier reportNotExists(string memory reportId) {
        require(!records[reportId].exists, "ForensicStorage: report already stored");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    // ── Core functions ────────────────────────────────────────────────────────

    /**
     * Store a report hash on-chain.
     * @param reportId  Unique case/report identifier (e.g. "CASE-001")
     * @param hexHash   SHA-256 hash of the report as a hex string (64 chars)
     *
     * Can only be called once per reportId (immutability guarantee).
     */
    function storeHash(string memory reportId, string memory hexHash)
        external
        reportNotExists(reportId)
    {
        require(bytes(reportId).length > 0, "ForensicStorage: empty reportId");
        require(bytes(hexHash).length == 64, "ForensicStorage: hash must be 64 hex chars");

        bytes32 hash = _hexToBytes32(hexHash);

        records[reportId] = ForensicRecord({
            reportHash: hash,
            storedBy:   msg.sender,
            storedAt:   block.timestamp,
            exists:     true
        });

        reportIds.push(reportId);

        emit HashStored(reportId, hash, msg.sender, block.timestamp);
    }

    /**
     * Verify a report hash against what is stored on-chain.
     * @param reportId  The report to verify
     * @param hexHash   The current hash to compare (recomputed from current report)
     * @return matched  true if the hashes match (report untampered)
     * @return storedAt Block timestamp when hash was originally stored
     * @return storedBy Address that stored the hash
     */
    function verifyHash(string memory reportId, string memory hexHash)
        external
        reportExists(reportId)
        returns (bool matched, uint256 storedAt, address storedBy)
    {
        ForensicRecord storage rec = records[reportId];
        bytes32 incoming = _hexToBytes32(hexHash);
        matched  = (rec.reportHash == incoming);
        storedAt = rec.storedAt;
        storedBy = rec.storedBy;

        emit HashVerified(reportId, matched, msg.sender, block.timestamp);
    }

    /**
     * Retrieve stored record metadata without re-verification.
     */
    function getRecord(string memory reportId)
        external
        view
        reportExists(reportId)
        returns (
            bytes32 reportHash,
            address storedBy,
            uint256 storedAt
        )
    {
        ForensicRecord storage rec = records[reportId];
        return (rec.reportHash, rec.storedBy, rec.storedAt);
    }

    /**
     * Return total number of stored reports.
     */
    function totalReports() external view returns (uint256) {
        return reportIds.length;
    }

    /**
     * Retrieve a reportId by index (for enumeration).
     */
    function getReportIdAt(uint256 index) external view returns (string memory) {
        require(index < reportIds.length, "ForensicStorage: index out of bounds");
        return reportIds[index];
    }

    /**
     * Check if a report is stored without reverting.
     */
    function reportStored(string memory reportId) external view returns (bool) {
        return records[reportId].exists;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    function _hexToBytes32(string memory hexStr) internal pure returns (bytes32 result) {
        bytes memory bstr = bytes(hexStr);
        require(bstr.length == 64, "ForensicStorage: invalid hex length");
        for (uint i = 0; i < 32; i++) {
            result |= bytes32(_hexCharToByte(bstr[2*i]) * 16 + _hexCharToByte(bstr[2*i+1])) >> (i * 8);
        }
    }

    function _hexCharToByte(bytes1 c) internal pure returns (uint8) {
        uint8 b = uint8(c);
        if (b >= 48 && b <= 57)  return b - 48;       // 0-9
        if (b >= 65 && b <= 70)  return b - 55;       // A-F
        if (b >= 97 && b <= 102) return b - 87;       // a-f
        revert("ForensicStorage: invalid hex char");
    }
}
