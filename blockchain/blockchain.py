"""
SPECTRA — Phase 5: Blockchain Module
======================================
Deploy ForensicStorage.sol to Ganache and interact with it via Web3.py.

Prerequisites:
  pip install web3 py-solc-x flask flask-cors

  # Install and use Ganache:
  npm install -g ganache
  ganache --port 7545 --accounts 10

Usage:
  # 1. Deploy contract
  python blockchain.py deploy

  # 2. Store a hash
  python blockchain.py store --report-id CASE-001 --hash <sha256hex>

  # 3. Verify a hash
  python blockchain.py verify --report-id CASE-001 --hash <sha256hex>

  # 4. Run as Flask microservice (called by Spring Boot)
  python blockchain.py serve
"""

import os
import sys
import json
import time
import hashlib
import logging
import argparse
from pathlib import Path
from datetime import datetime, timezone

log = logging.getLogger("spectra.blockchain")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

CONTRACT_PATH  = Path(__file__).parent / "ForensicStorage.sol"
DEPLOY_STATE   = Path(__file__).parent / "deployment.json"

RPC_URL        = os.getenv("BLOCKCHAIN_RPC",     "http://127.0.0.1:7545")
PRIVATE_KEY    = os.getenv("BLOCKCHAIN_PRIVATE_KEY", "")   # set from Ganache accounts


# ── Web3 helpers ──────────────────────────────────────────────────────────────

def get_web3():
    try:
        from web3 import Web3
        w3 = Web3(Web3.HTTPProvider(RPC_URL))
        if not w3.is_connected():
            raise ConnectionError(f"Cannot connect to Ethereum node at {RPC_URL}")
        log.info(f"Connected to Ethereum node: {RPC_URL}  (chainId={w3.eth.chain_id})")
        return w3
    except ImportError:
        log.error("web3 not installed. Run: pip install web3")
        sys.exit(1)


def get_account(w3):
    """Return the account to use for transactions."""
    if PRIVATE_KEY:
        from eth_account import Account
        acct = Account.from_key(PRIVATE_KEY)
        return acct.address, PRIVATE_KEY
    # Fall back to first unlocked Ganache account
    accounts = w3.eth.accounts
    if not accounts:
        raise RuntimeError("No accounts available")
    log.info(f"Using Ganache account: {accounts[0]}")
    return accounts[0], None


# ── Compilation ───────────────────────────────────────────────────────────────

def compile_contract() -> tuple[str, str]:
    import subprocess
    import json

    solc_path = r"C:\Users\Jnanika\solc\solc.exe"
    contract_file = str(CONTRACT_PATH)

    result = subprocess.run(
        [solc_path, "--combined-json", "abi,bin", contract_file],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        log.error(result.stderr)
        sys.exit(1)

    compiled = json.loads(result.stdout)

    contract_key = list(compiled["contracts"].keys())[0]
    contract_data = compiled["contracts"][contract_key]

    abi = contract_data["abi"]
    bytecode = contract_data["bin"]

    log.info(f"Compiled contract ({len(bytecode)//2} bytes)")
    return json.dumps(abi), bytecode


# ── Deployment ────────────────────────────────────────────────────────────────

def deploy() -> dict:
    """Deploy contract and save address to deployment.json."""
    w3 = get_web3()
    address, privkey = get_account(w3)
    abi_str, bytecode = compile_contract()
    abi = json.loads(abi_str)

    contract = w3.eth.contract(abi=abi, bytecode=bytecode)

    if privkey:
        # Signed transaction
        from eth_account import Account
        nonce = w3.eth.get_transaction_count(address)
        tx = contract.constructor().build_transaction({
            "from": address, "nonce": nonce,
            "gas": 2_000_000,
            "gasPrice": w3.to_wei("20", "gwei"),
        })
        signed = w3.eth.account.sign_transaction(tx, privkey)
        tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
    else:
        # Ganache (unlocked accounts)
        tx_hash = contract.constructor().transact({"from": address, "gas": 2_000_000})

    log.info(f"Waiting for receipt… tx={tx_hash.hex()}")
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
    contract_address = receipt.contractAddress

    state = {
        "contract_address": contract_address,
        "deployer":         address,
        "tx_hash":          receipt.transactionHash.hex(),
        "block_number":     receipt.blockNumber,
        "deployed_at":      datetime.now(tz=timezone.utc).isoformat(),
        "abi":              abi,
    }
    DEPLOY_STATE.write_text(json.dumps(state, indent=2))
    log.info(f"✔ Contract deployed at: {contract_address}")
    log.info(f"  Saved to: {DEPLOY_STATE}")
    return state


def load_deployment() -> dict:
    if not DEPLOY_STATE.exists():
        raise FileNotFoundError("Contract not deployed. Run: python blockchain.py deploy")
    return json.loads(DEPLOY_STATE.read_text())


def get_contract(w3):
    state = load_deployment()
    return w3.eth.contract(
        address=state["contract_address"],
        abi=state["abi"],
    ), state["contract_address"]


# ── Contract interactions ─────────────────────────────────────────────────────

def store_hash(report_id: str, hex_hash: str) -> dict:
    """Store a report hash on-chain."""
    w3 = get_web3()
    address, privkey = get_account(w3)
    contract, contract_addr = get_contract(w3)

    if privkey:
        nonce = w3.eth.get_transaction_count(address)
        tx = contract.functions.storeHash(report_id, hex_hash).build_transaction({
            "from": address, "nonce": nonce,
            "gas": 200_000,
            "gasPrice": w3.to_wei("20", "gwei"),
        })
        signed   = w3.eth.account.sign_transaction(tx, privkey)
        tx_hash  = w3.eth.send_raw_transaction(signed.rawTransaction)
    else:
        tx_hash = contract.functions.storeHash(report_id, hex_hash).transact({
            "from": address, "gas": 200_000
        })

    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
    log.info(f"✔ Hash stored on-chain: reportId={report_id}  tx={tx_hash.hex()}")

    return {
        "status":           "stored",
        "reportId":         report_id,
        "hash":             hex_hash,
        "txHash":           tx_hash.hex(),
        "blockNumber":      receipt.blockNumber,
        "contractAddress":  contract_addr,
        "timestamp":        datetime.now(tz=timezone.utc).isoformat(),
    }


def verify_hash(report_id: str, hex_hash: str) -> dict:
    """Verify a hash against the on-chain record."""
    w3 = get_web3()
    address, _ = get_account(w3)
    contract, contract_addr = get_contract(w3)

    # Check existence first (view call, free)
    exists = contract.functions.reportStored(report_id).call()
    if not exists:
        return {
            "status":    "not_found",
            "reportId":  report_id,
            "verified":  False,
            "message":   f"No record for report {report_id}",
        }

    # Read stored record
    stored_hash, stored_by, stored_at = contract.functions.getRecord(report_id).call()

    # Compare
    incoming_bytes32 = bytes.fromhex(hex_hash)
    stored_bytes     = bytes(stored_hash)
    matched = (incoming_bytes32 == stored_bytes[:len(incoming_bytes32)])

    result = {
        "status":          "verified" if matched else "tampered",
        "reportId":        report_id,
        "verified":        matched,
        "contractAddress": contract_addr,
        "storedAt":        datetime.fromtimestamp(stored_at, tz=timezone.utc).isoformat(),
        "storedBy":        stored_by,
        "providedHash":    hex_hash,
        "message":         "Integrity confirmed — hashes match." if matched
                           else "INTEGRITY VIOLATION — hashes differ!",
    }
    log.info(f"Verification: {result['status']} for report={report_id}")
    return result


# ── Flask microservice ────────────────────────────────────────────────────────

def run_server():
    """Expose blockchain operations as a small HTTP API for Spring Boot."""
    from flask import Flask, request, jsonify
    from flask_cors import CORS

    app = Flask(__name__)
    CORS(app)

    @app.route("/health", methods=["GET"])
    def health():
        try:
            w3 = get_web3()
            state = load_deployment()
            return jsonify({
                "status": "ok",
                "connected": True,
                "chainId": w3.eth.chain_id,
                "contractAddress": state.get("contract_address"),
                "blockNumber": w3.eth.block_number,
            })
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    @app.route("/store", methods=["POST"])
    def store():
        data = request.get_json()
        try:
            result = store_hash(data["reportId"], data["hash"])
            return jsonify(result)
        except Exception as e:
            log.exception("Store error")
            return jsonify({"status": "error", "message": str(e)}), 500

    @app.route("/verify", methods=["POST"])
    def verify():
        data = request.get_json()
        try:
            result = verify_hash(data["reportId"], data["hash"])
            return jsonify(result)
        except Exception as e:
            log.exception("Verify error")
            return jsonify({"status": "error", "message": str(e)}), 500

    @app.route("/records", methods=["GET"])
    def list_records():
        try:
            w3 = get_web3()
            contract, _ = get_contract(w3)
            total = contract.functions.totalReports().call()
            ids = [contract.functions.getReportIdAt(i).call() for i in range(min(total, 50))]
            return jsonify({"total": total, "reportIds": ids})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    port = int(os.getenv("BLOCKCHAIN_PORT", 5002))
    log.info(f"Blockchain microservice starting on port {port}")
    app.run(host="0.0.0.0", port=port, debug=False)


# ── CLI ───────────────────────────────────────────────────────────────────────

def sha256_of(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description="SPECTRA Blockchain Module")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("deploy", help="Deploy ForensicStorage contract to Ganache")

    p_store = sub.add_parser("store", help="Store a report hash on-chain")
    p_store.add_argument("--report-id", required=True)
    p_store.add_argument("--hash", required=True, help="64-char SHA-256 hex")

    p_verify = sub.add_parser("verify", help="Verify a report hash against on-chain record")
    p_verify.add_argument("--report-id", required=True)
    p_verify.add_argument("--hash", required=True)

    sub.add_parser("serve", help="Run as Flask microservice on port 5002")

    p_demo = sub.add_parser("demo", help="Full deploy + store + verify demo")

    args = parser.parse_args()

    if args.command == "deploy":
        result = deploy()
        print(json.dumps(result, indent=2))

    elif args.command == "store":
        result = store_hash(args.report_id, args.hash)
        print(json.dumps(result, indent=2))

    elif args.command == "verify":
        result = verify_hash(args.report_id, args.hash)
        print(json.dumps(result, indent=2))
        sys.exit(0 if result.get("verified") else 1)

    elif args.command == "serve":
        run_server()

    elif args.command == "demo":
        log.info("=== SPECTRA Blockchain Demo ===")
        state = deploy()
        report_id = "CASE-DEMO-001"
        report_content = f"Case: {report_id}\nEvidence: mimikatz.exe, tor browsing, C2 on 4444\nScore: 87/100"
        h = sha256_of(report_content)
        log.info(f"Report hash: {h}")
        store_result = store_hash(report_id, h)
        log.info(f"Stored: {store_result}")
        verify_result = verify_hash(report_id, h)
        log.info(f"Verified: {verify_result}")

        # Tamper test
        tampered_hash = sha256_of(report_content + " [MODIFIED]")
        tampered_result = verify_hash(report_id, tampered_hash)
        log.info(f"Tamper test: {tampered_result}")

        print("\n" + "="*50)
        print("Demo complete. Results:")
        print(json.dumps({"store": store_result, "verify": verify_result, "tamper_test": tampered_result}, indent=2))


if __name__ == "__main__":
    main()
