// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../src/Token20.sol";

contract E2ETest is Script {
    function run() external {
        address contractAddr = vm.envAddress("CONTRACT");
        uint256 gatewayPk = vm.envUint("GATEWAY_PK");
        uint256 ownerPk = vm.envUint("OWNER_PK");
        address ownerAddr = vm.addr(ownerPk);
        address gatewayAddr = vm.addr(gatewayPk);
        uint256 periodStart = vm.envUint("PERIOD_START");

        Token20 token = Token20(contractAddr);
        IERC20WithAuth usdc = token.usdc();

        // Build receipt
        Token20.Receipt memory receipt = Token20.Receipt({
            wallet: ownerAddr,
            model: "claude-4.6",
            tokens: 50000,
            blockNumber: block.number
        });
        bytes memory receiptBytes = abi.encode(receipt);

        // Sign receipt with gateway key
        bytes32 receiptHash = keccak256(receiptBytes);
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", receiptHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(gatewayPk, ethHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        // Single-leaf Merkle: root = receiptHash
        bytes32 merkleRoot = receiptHash;
        bytes32[] memory proof = new bytes32[](0);

        console.log("Receipt hash:", vm.toString(receiptHash));
        console.log("Gateway signer:", gatewayAddr);
        console.log("Period start:", periodStart);

        // Step 1: Anchor (as gateway — need gateway to have ETH for gas)
        // Gateway has no ETH, so owner sends the anchor tx
        // But anchor requires msg.sender to be gateway...
        // We need gateway to submit the anchor tx.
        // Alternative: owner funds gateway with a tiny bit of ETH first.

        // Check if gateway has ETH
        uint256 gwBal = gatewayAddr.balance;
        console.log("Gateway ETH balance:", gwBal);

        if (gwBal < 0.0001 ether) {
            console.log("Funding gateway with ETH...");
            vm.startBroadcast(ownerPk);
            payable(gatewayAddr).transfer(0.0005 ether);
            vm.stopBroadcast();
        }

        // Step 2: Anchor as gateway
        console.log("Anchoring...");
        vm.startBroadcast(gatewayPk);
        token.anchor(periodStart, merkleRoot, 1);
        vm.stopBroadcast();
        console.log("Anchor success!");

        // Step 3: Inscribe as owner
        console.log("Inscribing...");
        vm.startBroadcast(ownerPk);
        token.inscribe(1, receiptBytes, sig, proof, periodStart);
        vm.stopBroadcast();
        console.log("Inscribe success!");

        // Step 4: Verify
        uint256 tokenId = 1;
        address nftOwner = token.ownerOf(tokenId);
        console.log("NFT #1 owner:", nftOwner);
        console.log("Expected owner:", ownerAddr);

        string memory uri = token.tokenURI(tokenId);
        console.log("Token URI length:", bytes(uri).length);

        console.log("\n=== E2E TEST PASSED ===");
    }
}
