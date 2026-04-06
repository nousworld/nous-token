// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "../src/Token20.sol";

library DeployHelper {
    function deployToken20(address usdc, address treasury, address owner) internal returns (Token20) {
        Token20 impl = new Token20();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(impl),
            abi.encodeCall(Token20.initialize, (usdc, treasury, owner))
        );
        return Token20(address(proxy));
    }
}
