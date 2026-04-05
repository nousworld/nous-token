// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../src/Token20.sol";

contract DeployToken20 is Script {
    // Base Sepolia USDC: 0x036CbD53842c5426634e7929541eC2318f3dCF7e
    // Base Mainnet USDC: 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913

    function run() external {
        address usdc = vm.envAddress("USDC_ADDRESS");
        address gateway = vm.envAddress("GATEWAY_ADDRESS");

        vm.startBroadcast();

        Token20 token = new Token20(usdc);
        token.registerGateway(gateway);

        vm.stopBroadcast();

        console.log("Token20 deployed at:", address(token));
        console.log("Gateway registered:", gateway);
    }
}
