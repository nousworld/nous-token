// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/Token20.sol";
import "./DeployHelper.sol";

// ─── Shared Mock ───

contract MockUSDCAudit {
    string public name = "USD Coin";
    uint8 public decimals = 6;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => bool) public blacklisted;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function setBlacklist(address addr, bool val) external {
        blacklisted[addr] = val;
    }

    function transfer(address to, uint256 value) external returns (bool) {
        if (blacklisted[msg.sender] || blacklisted[to]) return false;
        if (balanceOf[msg.sender] < value) return false;
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        if (blacklisted[from] || blacklisted[to]) return false;
        if (allowance[from][msg.sender] < value) return false;
        if (balanceOf[from] < value) return false;
        allowance[from][msg.sender] -= value;
        balanceOf[from] -= value;
        balanceOf[to] += value;
        return true;
    }

    function transferWithAuthorization(
        address from, address to, uint256 value,
        uint256, uint256, bytes32, uint8, bytes32, bytes32
    ) external {
        require(!blacklisted[from] && !blacklisted[to], "Blacklisted");
        require(balanceOf[from] >= value, "Insufficient balance");
        balanceOf[from] -= value;
        balanceOf[to] += value;
    }
}

// ═══════════════════════════════════════════════════════════════════
// 1. FUZZ TESTS
// ══════════════��════════════════════════════════════════════════════

contract Token20FuzzTest is Test {
    Token20 public token;
    MockUSDCAudit public usdc;
    address treasuryAddr = address(0x7EEE);

    uint256 gatewayPk = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
    address gateway;

    function setUp() public {
        gateway = vm.addr(gatewayPk);
        vm.roll(1000);
        usdc = new MockUSDCAudit();
        token = DeployHelper.deployToken20(address(usdc), treasuryAddr, address(this));
        token.registerGateway(gateway);
    }

    /// @notice Fuzz _isSafeString: verify only [a-zA-Z0-9-._/ ] pass
    function testFuzz_safeStringRejectsUnsafe(bytes1 c) public {
        bytes memory b = new bytes(1);
        b[0] = c;
        string memory s = string(b);

        bool isAllowed =
            (c >= 0x30 && c <= 0x39) || // 0-9
            (c >= 0x41 && c <= 0x5A) || // A-Z
            (c >= 0x61 && c <= 0x7A) || // a-z
            c == 0x2D || c == 0x2E || c == 0x2F || c == 0x5F || c == 0x20;

        address creator = address(0xC4EA704);
        usdc.mint(creator, 5_000000);
        vm.startPrank(creator);
        usdc.approve(address(token), 5_000000);

        if (isAllowed) {
            token.deploy(s, "", 100, 10000, Token20.SeriesMode.OPEN, 1_000000);
        } else {
            vm.expectRevert("Name: unsafe characters");
            token.deploy(s, "", 100, 10000, Token20.SeriesMode.OPEN, 1_000000);
        }
        vm.stopPrank();
    }

    /// @notice Fuzz deploy fee: any fee >= minInscriptionFee should work
    function testFuzz_deployWithVariousFees(uint256 fee) public {
        fee = bound(fee, 1_000000, 100_000000);
        address creator = address(0xC4EA704);
        usdc.mint(creator, 5_000000 + fee);
        vm.startPrank(creator);
        usdc.approve(address(token), 5_000000);
        uint256 sid = token.deploy("FuzzSeries", "", 100, 10000, Token20.SeriesMode.OPEN, fee);
        vm.stopPrank();

        (,,,,,,, uint256 inscriptionFee,) = token.series(sid);
        assertEq(inscriptionFee, fee);
    }

    /// @notice Fuzz receipt balance tracking
    function testFuzz_receiptBalanceTracking(uint256 totalTokens, uint256 threshold, uint8 numInscribes) public {
        totalTokens = bound(totalTokens, 1000, 1_000_000);
        threshold = bound(threshold, 1, totalTokens);
        numInscribes = uint8(bound(numInscribes, 1, 20));

        uint256 maxPossible = totalTokens / threshold;
        if (maxPossible == 0) return;

        address alice = address(0xA11CE);
        address creator = address(0xC4EA704);

        usdc.mint(creator, 5_000000);
        usdc.mint(alice, uint256(numInscribes) * 1_000000 + 1_000000);

        vm.startPrank(creator);
        usdc.approve(address(token), 5_000000);
        uint256 sid = token.deploy("FuzzBalance", "", 1000, threshold, Token20.SeriesMode.OPEN, 1_000000);
        vm.stopPrank();

        bytes memory receipt = abi.encode(Token20.Receipt({
            wallet: alice, model: "claude-4.6", tokens: totalTokens, blockNumber: 500
        }));
        bytes32 receiptHash = keccak256(receipt);
        bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(receiptHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(gatewayPk, ethHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(gateway);
        token.anchor(300, receiptHash, 1);
        bytes32[] memory proof = new bytes32[](0);

        vm.startPrank(alice);
        usdc.approve(address(token), uint256(numInscribes) * 1_000000 + 1_000000);

        uint256 successCount = 0;
        for (uint256 i = 0; i < numInscribes; i++) {
            if (successCount >= maxPossible) {
                vm.expectRevert();
                token.inscribe(sid, receipt, sig, proof, 300);
                break;
            }
            token.inscribe(sid, receipt, sig, proof, 300);
            successCount++;
        }
        vm.stopPrank();

        assertEq(token.receiptUsed(receiptHash), successCount * threshold);
    }
}

// ═��══════════���══════════════════════════════════════════════════════
// 2. INVARIANT TESTS
// ═════════════���════════════════════════════���════════════════════════

contract Token20Handler is Test {
    Token20 public token;
    MockUSDCAudit public usdc;
    uint256 public gatewayPk;
    address public gateway;
    address public treasuryAddr;

    uint256[] public seriesIds;
    uint256 public nextCreatorSeed = 1;
    uint256 public nextPeriod = 300;

    constructor(Token20 _token, MockUSDCAudit _usdc, uint256 _gatewayPk, address _treasury) {
        token = _token;
        usdc = _usdc;
        gatewayPk = _gatewayPk;
        gateway = vm.addr(_gatewayPk);
        treasuryAddr = _treasury;
    }

    function deploySeries(uint256 feeSeed) external {
        uint256 fee = bound(feeSeed, 1_000000, 10_000000);
        address creator = address(uint160(0xC000 + nextCreatorSeed++));

        usdc.mint(creator, 5_000000);
        vm.startPrank(creator);
        usdc.approve(address(token), 5_000000);

        string memory name = string(abi.encodePacked("S", vm.toString(nextCreatorSeed)));
        try token.deploy(name, "", 1000, 10000, Token20.SeriesMode.OPEN, fee) returns (uint256 sid) {
            seriesIds.push(sid);
        } catch {}
        vm.stopPrank();
    }

    function inscribeOnSeries(uint256 seriesIdx) external {
        if (seriesIds.length == 0) return;
        seriesIdx = bound(seriesIdx, 0, seriesIds.length - 1);
        uint256 sid = seriesIds[seriesIdx];

        address alice = address(0xA11CE);
        usdc.mint(alice, 10_000000);

        bytes memory receipt = abi.encode(Token20.Receipt({
            wallet: alice, model: "claude-4.6", tokens: 100000, blockNumber: 500
        }));
        bytes32 receiptHash = keccak256(receipt);
        bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(receiptHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(gatewayPk, ethHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        uint256 period = nextPeriod;
        nextPeriod += 300;
        vm.roll(period + 100);

        vm.prank(gateway);
        try token.anchor(period, receiptHash, 1) {} catch { return; }

        bytes32[] memory proof = new bytes32[](0);

        vm.startPrank(alice);
        usdc.approve(address(token), 10_000000);
        try token.inscribe(sid, receipt, sig, proof, period) {} catch {}
        vm.stopPrank();
    }
}

contract Token20InvariantTest is Test {
    Token20 public token;
    MockUSDCAudit public usdc;
    Token20Handler public handler;
    address treasuryAddr = address(0x7EEE);

    uint256 gatewayPk = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;

    function setUp() public {
        vm.roll(1000);
        usdc = new MockUSDCAudit();
        token = DeployHelper.deployToken20(address(usdc), treasuryAddr, address(this));
        token.registerGateway(vm.addr(gatewayPk));

        handler = new Token20Handler(token, usdc, gatewayPk, treasuryAddr);
        targetContract(address(handler));
    }

    /// @notice Contract must ALWAYS hold zero USDC (push model invariant)
    function invariant_contractHoldsZeroUSDC() public view {
        assertEq(usdc.balanceOf(address(token)), 0, "Contract holds USDC - push model violated");
    }
}

// ��══════════════════════════════════════════════════════════════════
// 3. ATTACK SCENARIO TESTS
// ══════════���══════════════════════════════════��═════════════════════

contract Token20AttackTest is Test {
    Token20 public token;
    MockUSDCAudit public usdc;

    address owner = address(this);
    address treasuryAddr = address(0x7EEE);
    address alice = address(0xA11CE);
    address bob = address(0xB0B);
    address attacker = address(0xBAD);
    address creator = address(0xC4EA704);

    uint256 gatewayPk = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
    address gateway;

    function setUp() public {
        gateway = vm.addr(gatewayPk);
        vm.roll(1000);

        usdc = new MockUSDCAudit();
        token = DeployHelper.deployToken20(address(usdc), treasuryAddr, address(this));
        token.registerGateway(gateway);

        usdc.mint(alice, 1000_000000);
        usdc.mint(bob, 1000_000000);
        usdc.mint(attacker, 1000_000000);
        usdc.mint(creator, 1000_000000);
    }

    function _makeReceipt(address wallet, string memory model, uint256 tokens, uint256 blockNum)
        internal pure returns (bytes memory)
    {
        return abi.encode(Token20.Receipt({ wallet: wallet, model: model, tokens: tokens, blockNumber: blockNum }));
    }

    function _signReceipt(bytes memory receipt) internal view returns (bytes memory) {
        bytes32 hash = keccak256(receipt);
        bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(hash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(gatewayPk, ethHash);
        return abi.encodePacked(r, s, v);
    }

    function _emptyProof() internal pure returns (bytes32[] memory) {
        return new bytes32[](0);
    }

    // ─── M-2: Third-party receipt griefing blocked ───

    function test_attackThirdPartyInscribe_reverts() public {
        vm.startPrank(creator);
        usdc.approve(address(token), 5_000000);
        uint256 sid = token.deploy("CheapSeries", "", 100, 10000, Token20.SeriesMode.OPEN, 1_000000);
        vm.stopPrank();

        bytes memory receipt = _makeReceipt(alice, "claude-4.6", 50000, 12345);
        bytes memory sig = _signReceipt(receipt);
        bytes32 receiptHash = keccak256(receipt);

        vm.prank(gateway);
        token.anchor(300, receiptHash, 1);

        vm.startPrank(attacker);
        usdc.approve(address(token), 1_000000);
        vm.expectRevert("Not receipt owner");
        token.inscribe(sid, receipt, sig, _emptyProof(), 300);
        vm.stopPrank();

        assertEq(token.receiptUsed(receiptHash), 0);
    }

    // ─── Receipt balance exhaustion across series ───

    function test_receiptExhaustionCrossSeries() public {
        vm.startPrank(creator);
        usdc.approve(address(token), 10_000000);
        uint256 cheapSid = token.deploy("Cheap", "claude-4.6", 100, 10000, Token20.SeriesMode.OPEN, 1_000000);
        uint256 expensiveSid = token.deploy("Expensive", "claude-4.6", 100, 40000, Token20.SeriesMode.OPEN, 1_000000);
        vm.stopPrank();

        bytes memory receipt = _makeReceipt(alice, "claude-4.6", 50000, 12345);
        bytes memory sig = _signReceipt(receipt);
        bytes32 receiptHash = keccak256(receipt);

        vm.prank(gateway);
        token.anchor(300, receiptHash, 1);

        vm.startPrank(alice);
        usdc.approve(address(token), 10_000000);
        token.inscribe(cheapSid, receipt, sig, _emptyProof(), 300);
        token.inscribe(cheapSid, receipt, sig, _emptyProof(), 300);
        assertEq(token.receiptUsed(receiptHash), 20000);

        vm.expectRevert("Insufficient receipt balance");
        token.inscribe(expensiveSid, receipt, sig, _emptyProof(), 300);
        vm.stopPrank();
    }

    // ─── Revoked gateway signature rejected ───

    function test_revokedGatewaySignatureRejected() public {
        vm.startPrank(creator);
        usdc.approve(address(token), 5_000000);
        uint256 sid = token.deploy("RevokeTest", "claude-4.6", 100, 10000, Token20.SeriesMode.OPEN, 1_000000);
        vm.stopPrank();

        bytes memory receipt = _makeReceipt(alice, "claude-4.6", 50000, 12345);
        bytes memory sig = _signReceipt(receipt);
        bytes32 receiptHash = keccak256(receipt);

        vm.prank(gateway);
        token.anchor(300, receiptHash, 1);

        token.revokeGateway(gateway);

        vm.startPrank(alice);
        usdc.approve(address(token), 1_000000);
        vm.expectRevert("Invalid gateway signature");
        token.inscribe(sid, receipt, sig, _emptyProof(), 300);
        vm.stopPrank();
    }

    // ─── Anchor with zero root blocked ───

    function test_anchorEmptyRoot_reverts() public {
        vm.prank(gateway);
        vm.expectRevert("Empty root");
        token.anchor(300, bytes32(0), 1);
    }

    // ─── Creator blacklisted: inscribe still works, funds to treasury ───

    function test_creatorBlacklisted_inscribeSucceeds() public {
        vm.startPrank(creator);
        usdc.approve(address(token), 5_000000);
        uint256 sid = token.deploy("BlacklistTest", "claude-4.6", 100, 10000, Token20.SeriesMode.OPEN, 3_000000);
        vm.stopPrank();

        bytes memory receipt = _makeReceipt(alice, "claude-4.6", 50000, 12345);
        bytes memory sig = _signReceipt(receipt);
        bytes32 receiptHash = keccak256(receipt);

        vm.prank(gateway);
        token.anchor(300, receiptHash, 1);

        usdc.setBlacklist(creator, true);

        uint256 treasuryBefore = usdc.balanceOf(treasuryAddr);

        vm.startPrank(alice);
        usdc.approve(address(token), 3_000000);
        token.inscribe(sid, receipt, sig, _emptyProof(), 300);
        vm.stopPrank();

        assertEq(token.ownerOf(1), alice);
        // All 3 USDC to treasury (1 protocol + 2 creator fallback)
        assertEq(usdc.balanceOf(treasuryAddr) - treasuryBefore, 3_000000);
        assertEq(usdc.balanceOf(address(token)), 0);
    }

    // ─── Anchor invalidation and re-anchor ───

    function test_anchorInvalidateAndReanchor() public {
        vm.startPrank(creator);
        usdc.approve(address(token), 5_000000);
        uint256 sid = token.deploy("ReanchorTest", "claude-4.6", 100, 10000, Token20.SeriesMode.OPEN, 1_000000);
        vm.stopPrank();

        bytes memory receipt = _makeReceipt(alice, "claude-4.6", 50000, 12345);
        bytes memory sig = _signReceipt(receipt);
        bytes32 receiptHash = keccak256(receipt);

        vm.prank(gateway);
        token.anchor(300, receiptHash, 1);

        token.invalidateAnchor(300);

        vm.startPrank(alice);
        usdc.approve(address(token), 2_000000);
        vm.expectRevert("Period not anchored");
        token.inscribe(sid, receipt, sig, _emptyProof(), 300);
        vm.stopPrank();

        vm.prank(gateway);
        token.anchor(300, receiptHash, 1);

        vm.prank(alice);
        token.inscribe(sid, receipt, sig, _emptyProof(), 300);
        assertEq(token.ownerOf(1), alice);
    }

    // ─── CreatorPaymentFallback event ──��

    function test_creatorPaymentFallbackEvent() public {
        vm.startPrank(creator);
        usdc.approve(address(token), 5_000000);
        uint256 sid = token.deploy("FallbackEvt", "claude-4.6", 100, 10000, Token20.SeriesMode.OPEN, 2_000000);
        vm.stopPrank();

        bytes memory receipt = _makeReceipt(alice, "claude-4.6", 50000, 12345);
        bytes memory sig = _signReceipt(receipt);
        bytes32 receiptHash = keccak256(receipt);

        vm.prank(gateway);
        token.anchor(300, receiptHash, 1);

        usdc.setBlacklist(creator, true);

        vm.startPrank(alice);
        usdc.approve(address(token), 2_000000);
        vm.expectEmit(true, false, true, true);
        emit Token20.CreatorPaymentFallback(creator, 1_000000, sid);
        token.inscribe(sid, receipt, sig, _emptyProof(), 300);
        vm.stopPrank();
    }
}

// ═══════════════════════════════════════════════════════════════════
// 4. UUPS UPGRADE TESTS
// ═══════════════════════════════════════════════════════════════════

/// @notice Dummy V2 implementation for upgrade tests
contract Token20V2 is Token20 {
    function version() external pure returns (string memory) {
        return "v2";
    }
}

contract Token20UpgradeTest is Test {
    Token20 public token;
    MockUSDCAudit public usdc;
    address treasuryAddr = address(0x7EEE);
    address owner = address(this);
    address alice = address(0xA11CE);
    address creator = address(0xC4EA704);

    uint256 gatewayPk = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
    address gateway;

    function setUp() public {
        gateway = vm.addr(gatewayPk);
        vm.roll(1000);
        usdc = new MockUSDCAudit();
        token = DeployHelper.deployToken20(address(usdc), treasuryAddr, owner);
        token.registerGateway(gateway);
        usdc.mint(alice, 1000_000000);
        usdc.mint(creator, 1000_000000);
    }

    /// @notice Owner can upgrade to V2 and new function is available
    function test_upgradeToV2() public {
        // Create a series and inscribe before upgrade
        vm.startPrank(creator);
        usdc.approve(address(token), 5_000000);
        uint256 sid = token.deploy("PreUpgrade", "claude-4.6", 100, 10000, Token20.SeriesMode.OPEN, 1_000000);
        vm.stopPrank();

        // Upgrade
        Token20V2 v2impl = new Token20V2();
        token.upgradeToAndCall(address(v2impl), "");

        // V2 function works
        Token20V2 v2 = Token20V2(address(token));
        assertEq(v2.version(), "v2");

        // State preserved: series still exists
        (string memory name,,,,,,,, ) = v2.series(sid);
        assertEq(name, "PreUpgrade");

        // Can still inscribe after upgrade
        bytes memory receipt = abi.encode(Token20.Receipt({
            wallet: alice, model: "claude-4.6", tokens: 50000, blockNumber: 500
        }));
        bytes32 receiptHash = keccak256(receipt);
        bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(receiptHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(gatewayPk, ethHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(gateway);
        token.anchor(300, receiptHash, 1);

        vm.startPrank(alice);
        usdc.approve(address(token), 1_000000);
        v2.inscribe(sid, receipt, sig, new bytes32[](0), 300);
        vm.stopPrank();

        assertEq(v2.ownerOf(1), alice);
    }

    /// @notice Non-owner cannot upgrade
    function test_upgradeNonOwner_reverts() public {
        Token20V2 v2impl = new Token20V2();
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", alice));
        token.upgradeToAndCall(address(v2impl), "");
    }

    /// @notice Implementation contract cannot be initialized directly
    function test_implementationCannotBeInitialized() public {
        Token20 impl = new Token20();
        vm.expectRevert();
        impl.initialize(address(usdc), treasuryAddr, owner);
    }

    /// @notice Double initialization is blocked
    function test_doubleInitialize_reverts() public {
        vm.expectRevert();
        token.initialize(address(usdc), treasuryAddr, owner);
    }
}

// ═══════════════════════════════════════════════════════════════════
// 5. INSCRIBE-WITH-PERMIT (RELAYER) TESTS
// ═══════════════════════════════════════════════════════════════════

/// @notice MockUSDC with EIP-2612 permit support
contract MockUSDCPermit is MockUSDCAudit {
    mapping(address => uint256) public nonces;

    // Simplified permit: just approve (skip real EIP-2612 signature verification in mock)
    function permit(
        address owner_,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8,
        bytes32,
        bytes32
    ) external {
        require(deadline >= block.timestamp, "Permit expired");
        require(!blacklisted[owner_], "Blacklisted");
        allowance[owner_][spender] = value;
    }
}

contract Token20InscribeWithPermitTest is Test {
    Token20 public token;
    MockUSDCPermit public usdc;
    address treasuryAddr = address(0x7EEE);
    address owner = address(this);
    address creator = address(0xC4EA704);
    address relayer = address(0xABCD);

    uint256 gatewayPk = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
    address gateway;

    uint256 alicePk = 0xA11CE00000000000000000000000000000000000000000000000000000000001;
    address alice;

    function setUp() public {
        alice = vm.addr(alicePk);
        gateway = vm.addr(gatewayPk);
        vm.roll(1000);

        usdc = new MockUSDCPermit();
        token = DeployHelper.deployToken20(address(usdc), treasuryAddr, owner);
        token.registerGateway(gateway);

        usdc.mint(alice, 1000_000000);
        usdc.mint(creator, 1000_000000);
    }

    function _makeReceipt(address wallet, string memory model, uint256 tokens, uint256 blockNum)
        internal pure returns (bytes memory)
    {
        return abi.encode(Token20.Receipt({ wallet: wallet, model: model, tokens: tokens, blockNumber: blockNum }));
    }

    function _signReceipt(bytes memory receipt) internal view returns (bytes memory) {
        bytes32 hash = keccak256(receipt);
        bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(hash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(gatewayPk, ethHash);
        return abi.encodePacked(r, s, v);
    }

    /// @dev Sign EIP-712 inscribe authorization as alice
    function _signInscribeAuth(uint256 seriesId, bytes memory receipt, uint256 periodStart, uint256 nonce)
        internal view returns (uint8 v, bytes32 r, bytes32 s)
    {
        bytes32 structHash = keccak256(abi.encode(
            token.INSCRIBE_AUTH_TYPEHASH(),
            seriesId,
            keccak256(receipt),
            periodStart,
            nonce
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", token.DOMAIN_SEPARATOR(), structHash));
        (v, r, s) = vm.sign(alicePk, digest);
    }

    /// @notice Happy path: relayer submits inscribeWithPermit, wallet pays USDC via permit
    function test_inscribeWithPermit_happyPath() public {
        vm.startPrank(creator);
        usdc.approve(address(token), 5_000000);
        uint256 sid = token.deploy("PermitTest", "claude-4.6", 100, 10000, Token20.SeriesMode.OPEN, 2_000000);
        vm.stopPrank();

        bytes memory receipt = _makeReceipt(alice, "claude-4.6", 50000, 12345);
        bytes memory gatewaySig = _signReceipt(receipt);
        bytes32 receiptHash = keccak256(receipt);

        vm.prank(gateway);
        token.anchor(300, receiptHash, 1);

        // Alice signs EIP-712 inscribe auth
        (uint8 authV, bytes32 authR, bytes32 authS) = _signInscribeAuth(sid, receipt, 300, 0);

        uint256 aliceBefore = usdc.balanceOf(alice);
        uint256 treasuryBefore = usdc.balanceOf(treasuryAddr);
        uint256 creatorBefore = usdc.balanceOf(creator);

        // Relayer submits (permit params: mock doesn't verify sig, just approves)
        vm.prank(relayer);
        token.inscribeWithPermit(
            sid, receipt, gatewaySig, new bytes32[](0), 300,
            type(uint256).max, // permitDeadline
            28, bytes32(0), bytes32(0), // permit v,r,s (mock accepts any)
            authV, authR, authS
        );

        assertEq(token.ownerOf(1), alice);
        assertEq(aliceBefore - usdc.balanceOf(alice), 2_000000);
        assertEq(usdc.balanceOf(treasuryAddr) - treasuryBefore, 1_000000);
        assertEq(usdc.balanceOf(creator) - creatorBefore, 1_000000);
        assertEq(usdc.balanceOf(address(token)), 0);
        assertEq(token.inscribeNonce(alice), 1);
    }

    /// @notice Replay same auth — nonce mismatch, reverts
    function test_inscribeWithPermit_replayReverts() public {
        vm.startPrank(creator);
        usdc.approve(address(token), 5_000000);
        uint256 sid = token.deploy("ReplayTest", "claude-4.6", 100, 10000, Token20.SeriesMode.OPEN, 1_000000);
        vm.stopPrank();

        bytes memory receipt = _makeReceipt(alice, "claude-4.6", 50000, 12345);
        bytes memory gatewaySig = _signReceipt(receipt);

        vm.prank(gateway);
        token.anchor(300, keccak256(receipt), 1);

        (uint8 authV, bytes32 authR, bytes32 authS) = _signInscribeAuth(sid, receipt, 300, 0);

        vm.prank(relayer);
        token.inscribeWithPermit(
            sid, receipt, gatewaySig, new bytes32[](0), 300,
            type(uint256).max, 28, bytes32(0), bytes32(0),
            authV, authR, authS
        );

        // Replay — nonce incremented, old sig invalid
        vm.prank(relayer);
        vm.expectRevert("Invalid inscribe auth");
        token.inscribeWithPermit(
            sid, receipt, gatewaySig, new bytes32[](0), 300,
            type(uint256).max, 28, bytes32(0), bytes32(0),
            authV, authR, authS
        );
    }

    /// @notice Wrong signer — reverts
    function test_inscribeWithPermit_wrongSigner_reverts() public {
        vm.startPrank(creator);
        usdc.approve(address(token), 5_000000);
        uint256 sid = token.deploy("WrongSig", "claude-4.6", 100, 10000, Token20.SeriesMode.OPEN, 1_000000);
        vm.stopPrank();

        bytes memory receipt = _makeReceipt(alice, "claude-4.6", 50000, 12345);
        bytes memory gatewaySig = _signReceipt(receipt);

        vm.prank(gateway);
        token.anchor(300, keccak256(receipt), 1);

        // Attacker signs EIP-712 (not alice)
        uint256 attackerPk = 0xBAD0000000000000000000000000000000000000000000000000000000000001;
        bytes32 structHash = keccak256(abi.encode(
            token.INSCRIBE_AUTH_TYPEHASH(), sid, keccak256(receipt), uint256(300), uint256(0)
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", token.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(attackerPk, digest);

        vm.prank(relayer);
        vm.expectRevert("Invalid inscribe auth");
        token.inscribeWithPermit(
            sid, receipt, gatewaySig, new bytes32[](0), 300,
            type(uint256).max, 28, bytes32(0), bytes32(0),
            v, r, s
        );
    }

    /// @notice Multiple inscribes with incrementing nonces
    function test_inscribeWithPermit_multipleNonces() public {
        vm.startPrank(creator);
        usdc.approve(address(token), 5_000000);
        uint256 sid = token.deploy("MultiNonce", "claude-4.6", 100, 10000, Token20.SeriesMode.OPEN, 1_000000);
        vm.stopPrank();

        bytes memory receipt = _makeReceipt(alice, "claude-4.6", 50000, 12345);
        bytes memory gatewaySig = _signReceipt(receipt);

        vm.prank(gateway);
        token.anchor(300, keccak256(receipt), 1);

        for (uint256 i = 0; i < 3; i++) {
            (uint8 authV, bytes32 authR, bytes32 authS) = _signInscribeAuth(sid, receipt, 300, i);
            vm.prank(relayer);
            token.inscribeWithPermit(
                sid, receipt, gatewaySig, new bytes32[](0), 300,
                type(uint256).max, 28, bytes32(0), bytes32(0),
                authV, authR, authS
            );
            assertEq(token.inscribeNonce(alice), i + 1);
        }
        assertEq(token.receiptUsed(keccak256(receipt)), 30000);
    }
}
