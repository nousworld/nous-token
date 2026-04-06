// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "../src/Token20.sol";

contract DeployToken20 is Script {
    // Base Mainnet USDC: 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913

    function run() external {
        address usdc = vm.envAddress("USDC_ADDRESS");
        address gateway = vm.envAddress("GATEWAY_ADDRESS");
        address treasury = vm.envAddress("TREASURY_ADDRESS");

        vm.startBroadcast();

        // Deploy implementation
        Token20 impl = new Token20();

        // Deploy proxy pointing to implementation, calling initialize
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(impl),
            abi.encodeCall(Token20.initialize, (usdc, treasury, msg.sender))
        );

        Token20 token = Token20(address(proxy));
        token.registerGateway(gateway);

        vm.stopBroadcast();

        console.log("Implementation deployed at:", address(impl));
        console.log("Proxy (Token20) deployed at:", address(proxy));
        console.log("Treasury:", treasury);
        console.log("Gateway registered:", gateway);
        console.log("Owner:", msg.sender);
    }
}
