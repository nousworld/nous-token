// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/Token20.sol";
import "./DeployHelper.sol";

contract MockUSDC {
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

contract Token20Test is Test {
    Token20 public token;
    MockUSDC public usdc;

    address owner = address(this);
    address treasuryAddr = address(0x7EEE);
    address alice = address(0xA11CE);
    address bob = address(0xB0B);
    address creator = address(0xC4EA704);

    uint256 gatewayPk;
    address gateway;

    function setUp() public {
        gatewayPk = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
        gateway = vm.addr(gatewayPk);

        vm.roll(1000);

        usdc = new MockUSDC();
        token = DeployHelper.deployToken20(address(usdc), treasuryAddr, address(this));

        token.registerGateway(gateway);

        usdc.mint(alice, 1000_000000);
        usdc.mint(bob, 1000_000000);
        usdc.mint(creator, 1000_000000);
    }

    // ─── Helpers ───

    function _createTestSeries() internal returns (uint256) {
        vm.startPrank(creator);
        usdc.approve(address(token), 5_000000);
        uint256 sid = token.deploy("TestSeries", "claude-4.6", 100, 10000, Token20.SeriesMode.OPEN, 1_000000);
        vm.stopPrank();
        return sid;
    }

    function _makeReceipt(address wallet, string memory model, uint256 tokens, uint256 blockNum)
        internal pure returns (bytes memory)
    {
        return abi.encode(Token20.Receipt({
            wallet: wallet,
            model: model,
            tokens: tokens,
            blockNumber: blockNum
        }));
    }

    function _signReceipt(bytes memory receipt) internal view returns (bytes memory) {
        bytes32 hash = keccak256(receipt);
        bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(hash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(gatewayPk, ethHash);
        return abi.encodePacked(r, s, v);
    }

    function _anchorAndGetProof(bytes memory receipt) internal returns (bytes32[] memory, uint256) {
        bytes32 receiptHash = keccak256(receipt);
        uint256 periodStart = 300;

        vm.prank(gateway);
        token.anchor(periodStart, receiptHash, 1);

        bytes32[] memory proof = new bytes32[](0);
        return (proof, periodStart);
    }

    function _anchorMultiLeaf(bytes memory receipt1, bytes memory receipt2)
        internal returns (bytes32[] memory proof1, bytes32[] memory proof2, uint256 periodStart)
    {
        bytes32 hash1 = keccak256(receipt1);
        bytes32 hash2 = keccak256(receipt2);

        bytes32 left;
        bytes32 right;
        if (hash1 < hash2) { left = hash1; right = hash2; }
        else { left = hash2; right = hash1; }

        bytes32 root = keccak256(abi.encodePacked(left, right));
        periodStart = 300;

        vm.prank(gateway);
        token.anchor(periodStart, root, 2);

        proof1 = new bytes32[](1);
        proof1[0] = hash2;

        proof2 = new bytes32[](1);
        proof2[0] = hash1;
    }

    // ─── Deploy Series Tests ───

    function test_deploySeries() public {
        uint256 treasuryBefore = usdc.balanceOf(treasuryAddr);
        vm.startPrank(creator);
        usdc.approve(address(token), 5_000000);
        uint256 sid = token.deploy("Opus", "claude-4.6", 210000, 10000, Token20.SeriesMode.OPEN, 2_000000);
        vm.stopPrank();

        assertEq(sid, 1);
        // Deploy fee goes directly to treasury
        assertEq(usdc.balanceOf(treasuryAddr) - treasuryBefore, 5_000000);
        // Contract holds zero
        assertEq(usdc.balanceOf(address(token)), 0);
    }

    function test_deployDuplicateName_reverts() public {
        vm.startPrank(creator);
        usdc.approve(address(token), 10_000000);
        token.deploy("Opus", "claude-4.6", 210000, 10000, Token20.SeriesMode.OPEN, 2_000000);
        vm.expectRevert("Name taken");
        token.deploy("Opus", "gpt-4", 100000, 5000, Token20.SeriesMode.OPEN, 1_000000);
        vm.stopPrank();
    }

    function test_deployFeeTooLow_reverts() public {
        vm.startPrank(creator);
        usdc.approve(address(token), 5_000000);
        vm.expectRevert("Fee below minimum");
        token.deploy("Cheap", "claude-4.6", 210000, 10000, Token20.SeriesMode.OPEN, 500000);
        vm.stopPrank();
    }

    function test_deployEmptyName_reverts() public {
        vm.startPrank(creator);
        usdc.approve(address(token), 5_000000);
        vm.expectRevert("Name: 1-32 bytes");
        token.deploy("", "claude-4.6", 100, 10000, Token20.SeriesMode.OPEN, 1_000000);
        vm.stopPrank();
    }

    function test_deployLongName_reverts() public {
        vm.startPrank(creator);
        usdc.approve(address(token), 5_000000);
        vm.expectRevert("Name: 1-32 bytes");
        token.deploy("ThisNameIsWayTooLongForTheLimitXX", "claude-4.6", 100, 10000, Token20.SeriesMode.OPEN, 1_000000);
        vm.stopPrank();
    }

    function test_deployWithAuth() public {
        usdc.mint(alice, 5_000000);
        vm.prank(alice);
        uint256 sid = token.deployWithAuth(
            "AuthSeries", "claude-4.6", 100, 10000, Token20.SeriesMode.OPEN, 1_000000,
            alice, 5_000000, 0, type(uint256).max, bytes32(uint256(1)), 27, bytes32(0), bytes32(0)
        );

        (,,,,,, address seriesCreator,,) = token.series(sid);
        assertEq(seriesCreator, alice);
        // Deploy fee went to treasury
        assertEq(usdc.balanceOf(address(token)), 0);
    }

    function test_deployWithAuth_wrongValue_reverts() public {
        vm.prank(alice);
        vm.expectRevert("Value must equal deploy fee");
        token.deployWithAuth(
            "Bad", "claude-4.6", 100, 10000, Token20.SeriesMode.OPEN, 1_000000,
            alice, 10_000000, 0, type(uint256).max, bytes32(uint256(1)), 27, bytes32(0), bytes32(0)
        );
    }

    // ─── Inscribe Tests ───

    function test_inscribe() public {
        uint256 sid = _createTestSeries();
        bytes memory receipt = _makeReceipt(alice, "claude-4.6", 50000, 12345);
        bytes memory sig = _signReceipt(receipt);
        (bytes32[] memory proof, uint256 period) = _anchorAndGetProof(receipt);

        uint256 treasuryBefore = usdc.balanceOf(treasuryAddr);

        vm.startPrank(alice);
        usdc.approve(address(token), 1_000000);
        token.inscribe(sid, receipt, sig, proof, period);
        vm.stopPrank();

        assertEq(token.ownerOf(1), alice);
        assertEq(token.receiptUsed(keccak256(receipt)), 10000);
        // Fee = 1 USDC (min), all goes to treasury (no creator share at min fee)
        assertEq(usdc.balanceOf(treasuryAddr) - treasuryBefore, 1_000000);
        // Contract holds zero
        assertEq(usdc.balanceOf(address(token)), 0);
    }

    function test_inscribeMultipleFromSameReceipt() public {
        uint256 sid = _createTestSeries();
        bytes memory receipt = _makeReceipt(alice, "claude-4.6", 50000, 12345);
        bytes memory sig = _signReceipt(receipt);
        (bytes32[] memory proof, uint256 period) = _anchorAndGetProof(receipt);

        vm.startPrank(alice);
        usdc.approve(address(token), 6_000000);

        for (uint i = 0; i < 5; i++) {
            token.inscribe(sid, receipt, sig, proof, period);
        }

        vm.expectRevert("Insufficient receipt balance");
        token.inscribe(sid, receipt, sig, proof, period);
        vm.stopPrank();

        assertEq(token.receiptUsed(keccak256(receipt)), 50000);
    }

    function test_inscribeModelMismatch_reverts() public {
        uint256 sid = _createTestSeries();
        bytes memory receipt = _makeReceipt(alice, "gpt-4", 50000, 12345);
        bytes memory sig = _signReceipt(receipt);
        (bytes32[] memory proof, uint256 period) = _anchorAndGetProof(receipt);

        vm.startPrank(alice);
        usdc.approve(address(token), 1_000000);
        vm.expectRevert("Model mismatch");
        token.inscribe(sid, receipt, sig, proof, period);
        vm.stopPrank();
    }

    function test_inscribeWildcardModel() public {
        vm.startPrank(creator);
        usdc.approve(address(token), 5_000000);
        uint256 sid = token.deploy("AnyModel", "", 100, 10000, Token20.SeriesMode.OPEN, 1_000000);
        vm.stopPrank();

        bytes memory receipt = _makeReceipt(alice, "deepseek-v3", 50000, 12345);
        bytes memory sig = _signReceipt(receipt);
        (bytes32[] memory proof, uint256 period) = _anchorAndGetProof(receipt);

        vm.startPrank(alice);
        usdc.approve(address(token), 1_000000);
        token.inscribe(sid, receipt, sig, proof, period);
        vm.stopPrank();

        assertEq(token.ownerOf(1), alice);
    }

    function test_inscribeRestrictedMode() public {
        vm.startPrank(creator);
        usdc.approve(address(token), 5_000000);
        uint256 sid = token.deploy("Restricted", "claude-4.6", 100, 10000, Token20.SeriesMode.RESTRICTED, 1_000000);
        token.authorize(sid, alice);
        vm.stopPrank();

        bytes memory receipt = _makeReceipt(alice, "claude-4.6", 50000, 12345);
        bytes memory sig = _signReceipt(receipt);
        (bytes32[] memory proof, uint256 period) = _anchorAndGetProof(receipt);

        vm.startPrank(alice);
        usdc.approve(address(token), 1_000000);
        token.inscribe(sid, receipt, sig, proof, period);
        vm.stopPrank();
        assertEq(token.ownerOf(1), alice);
    }

    function test_inscribeRestrictedUnauthorized_reverts() public {
        vm.startPrank(creator);
        usdc.approve(address(token), 5_000000);
        uint256 sid = token.deploy("Restricted2", "claude-4.6", 100, 10000, Token20.SeriesMode.RESTRICTED, 1_000000);
        vm.stopPrank();

        bytes memory receipt = _makeReceipt(bob, "claude-4.6", 50000, 12345);
        bytes memory sig = _signReceipt(receipt);
        (bytes32[] memory proof, uint256 period) = _anchorAndGetProof(receipt);

        vm.startPrank(bob);
        usdc.approve(address(token), 1_000000);
        vm.expectRevert("Not authorized");
        token.inscribe(sid, receipt, sig, proof, period);
        vm.stopPrank();
    }

    function test_inscribeInvalidGateway_reverts() public {
        uint256 sid = _createTestSeries();
        bytes memory receipt = _makeReceipt(alice, "claude-4.6", 50000, 12345);

        uint256 fakePk = 0xDEAD;
        bytes32 hash = keccak256(receipt);
        bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(hash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(fakePk, ethHash);
        bytes memory fakeSig = abi.encodePacked(r, s, v);

        (bytes32[] memory proof, uint256 period) = _anchorAndGetProof(receipt);

        vm.startPrank(alice);
        usdc.approve(address(token), 1_000000);
        vm.expectRevert("Invalid gateway signature");
        token.inscribe(sid, receipt, fakeSig, proof, period);
        vm.stopPrank();
    }

    function test_inscribeWithAuth() public {
        uint256 sid = _createTestSeries();
        bytes memory receipt = _makeReceipt(alice, "claude-4.6", 50000, 12345);
        bytes memory sig = _signReceipt(receipt);
        (bytes32[] memory proof, uint256 period) = _anchorAndGetProof(receipt);

        usdc.mint(alice, 1_000000);
        vm.prank(alice);
        token.inscribeWithAuth(
            sid, receipt, sig, proof, period,
            alice, 1_000000, 0, type(uint256).max, bytes32(uint256(99)), 27, bytes32(0), bytes32(0)
        );

        assertEq(token.ownerOf(1), alice);
        // Contract holds zero after inscribeWithAuth
        assertEq(usdc.balanceOf(address(token)), 0);
    }

    function test_inscribeWithAuth_wrongValue_reverts() public {
        uint256 sid = _createTestSeries();
        bytes memory receipt = _makeReceipt(alice, "claude-4.6", 50000, 12345);
        bytes memory sig = _signReceipt(receipt);
        (bytes32[] memory proof, uint256 period) = _anchorAndGetProof(receipt);

        vm.prank(alice);
        vm.expectRevert("Value must equal inscription fee");
        token.inscribeWithAuth(
            sid, receipt, sig, proof, period,
            alice, 999999, 0, type(uint256).max, bytes32(uint256(99)), 27, bytes32(0), bytes32(0)
        );
    }

    // ─── Multi-leaf Merkle Tests ───

    function test_inscribeMultiLeafMerkle() public {
        uint256 sid = _createTestSeries();
        bytes memory receipt1 = _makeReceipt(alice, "claude-4.6", 50000, 12345);
        bytes memory receipt2 = _makeReceipt(bob, "claude-4.6", 30000, 12346);
        bytes memory sig1 = _signReceipt(receipt1);
        bytes memory sig2 = _signReceipt(receipt2);

        (bytes32[] memory proof1, bytes32[] memory proof2, uint256 period) =
            _anchorMultiLeaf(receipt1, receipt2);

        vm.startPrank(alice);
        usdc.approve(address(token), 1_000000);
        token.inscribe(sid, receipt1, sig1, proof1, period);
        vm.stopPrank();

        vm.startPrank(bob);
        usdc.approve(address(token), 1_000000);
        token.inscribe(sid, receipt2, sig2, proof2, period);
        vm.stopPrank();

        assertEq(token.ownerOf(1), alice);
        assertEq(token.ownerOf(2), bob);
    }

    // ─── Receipt Cross-Series Tests ───

    function test_receiptBalanceCrossSeries() public {
        vm.startPrank(creator);
        usdc.approve(address(token), 10_000000);
        uint256 sid1 = token.deploy("SeriesA", "claude-4.6", 100, 10000, Token20.SeriesMode.OPEN, 1_000000);
        uint256 sid2 = token.deploy("SeriesB", "claude-4.6", 100, 25000, Token20.SeriesMode.OPEN, 1_000000);
        vm.stopPrank();

        bytes memory receipt = _makeReceipt(alice, "claude-4.6", 50000, 12345);
        bytes memory sig = _signReceipt(receipt);
        (bytes32[] memory proof, uint256 period) = _anchorAndGetProof(receipt);

        vm.startPrank(alice);
        usdc.approve(address(token), 5_000000);

        token.inscribe(sid1, receipt, sig, proof, period);
        token.inscribe(sid1, receipt, sig, proof, period);
        assertEq(token.receiptUsed(keccak256(receipt)), 20000);

        token.inscribe(sid2, receipt, sig, proof, period);
        assertEq(token.receiptUsed(keccak256(receipt)), 45000);

        vm.expectRevert("Insufficient receipt balance");
        token.inscribe(sid1, receipt, sig, proof, period);
        vm.stopPrank();
    }

    // ─── Fee Distribution Tests (Push Model) ───

    function test_feeDistribution_creatorGetsShare() public {
        // Fee = 3 USDC. Protocol gets 1, creator gets 2.
        vm.startPrank(creator);
        usdc.approve(address(token), 5_000000);
        uint256 sid = token.deploy("Premium", "claude-4.6", 100, 10000, Token20.SeriesMode.OPEN, 3_000000);
        vm.stopPrank();

        bytes memory receipt = _makeReceipt(alice, "claude-4.6", 50000, 12345);
        bytes memory sig = _signReceipt(receipt);
        (bytes32[] memory proof, uint256 period) = _anchorAndGetProof(receipt);

        uint256 treasuryBefore = usdc.balanceOf(treasuryAddr);
        uint256 creatorBefore = usdc.balanceOf(creator);

        vm.startPrank(alice);
        usdc.approve(address(token), 3_000000);
        token.inscribe(sid, receipt, sig, proof, period);
        vm.stopPrank();

        // Treasury got protocol fee (1 USDC)
        assertEq(usdc.balanceOf(treasuryAddr) - treasuryBefore, 1_000000);
        // Creator got share (2 USDC)
        assertEq(usdc.balanceOf(creator) - creatorBefore, 2_000000);
        // Contract holds zero
        assertEq(usdc.balanceOf(address(token)), 0);
    }

    function test_feeDistribution_minFeeNoCreatorShare() public {
        // At minimum fee (1 USDC = PROTOCOL_FEE), creator gets nothing
        uint256 sid = _createTestSeries(); // 1 USDC fee

        bytes memory receipt = _makeReceipt(alice, "claude-4.6", 50000, 12345);
        bytes memory sig = _signReceipt(receipt);
        (bytes32[] memory proof, uint256 period) = _anchorAndGetProof(receipt);

        uint256 creatorBefore = usdc.balanceOf(creator);

        vm.startPrank(alice);
        usdc.approve(address(token), 1_000000);
        token.inscribe(sid, receipt, sig, proof, period);
        vm.stopPrank();

        // Creator balance unchanged
        assertEq(usdc.balanceOf(creator), creatorBefore);
    }

    function test_feeDistribution_creatorBlacklisted_fallbackToTreasury() public {
        // Creator is USDC-blacklisted — their share should go to treasury
        vm.startPrank(creator);
        usdc.approve(address(token), 5_000000);
        uint256 sid = token.deploy("Blacklist", "claude-4.6", 100, 10000, Token20.SeriesMode.OPEN, 3_000000);
        vm.stopPrank();

        bytes memory receipt = _makeReceipt(alice, "claude-4.6", 50000, 12345);
        bytes memory sig = _signReceipt(receipt);
        (bytes32[] memory proof, uint256 period) = _anchorAndGetProof(receipt);

        // Blacklist creator AFTER deploy
        usdc.setBlacklist(creator, true);

        uint256 treasuryBefore = usdc.balanceOf(treasuryAddr);

        vm.startPrank(alice);
        usdc.approve(address(token), 3_000000);
        token.inscribe(sid, receipt, sig, proof, period);
        vm.stopPrank();

        // All 3 USDC went to treasury (1 protocol + 2 creator fallback)
        assertEq(usdc.balanceOf(treasuryAddr) - treasuryBefore, 3_000000);
        // Inscribe succeeded — not blocked by creator blacklist
        assertEq(token.ownerOf(1), alice);
        // Contract holds zero
        assertEq(usdc.balanceOf(address(token)), 0);
    }

    function test_feeDistribution_multipleCreatorsIsolated() public {
        address creator2 = address(0xC4EA702);
        usdc.mint(creator2, 1000_000000);

        vm.startPrank(creator);
        usdc.approve(address(token), 5_000000);
        uint256 sid1 = token.deploy("Series1", "claude-4.6", 100, 10000, Token20.SeriesMode.OPEN, 2_000000);
        vm.stopPrank();

        vm.startPrank(creator2);
        usdc.approve(address(token), 5_000000);
        uint256 sid2 = token.deploy("Series2", "claude-4.6", 100, 10000, Token20.SeriesMode.OPEN, 2_000000);
        vm.stopPrank();

        bytes memory receipt1 = _makeReceipt(alice, "claude-4.6", 50000, 12345);
        bytes memory sig1 = _signReceipt(receipt1);
        (bytes32[] memory proof1, uint256 period1) = _anchorAndGetProof(receipt1);

        uint256 creator1Before = usdc.balanceOf(creator);
        uint256 creator2Before = usdc.balanceOf(creator2);

        vm.startPrank(alice);
        usdc.approve(address(token), 4_000000);
        token.inscribe(sid1, receipt1, sig1, proof1, period1);

        bytes memory receipt2 = _makeReceipt(alice, "claude-4.6", 60000, 12346);
        bytes memory sig2 = _signReceipt(receipt2);
        bytes32 hash2 = keccak256(receipt2);
        vm.stopPrank();

        vm.prank(gateway);
        token.anchor(600, hash2, 1);
        bytes32[] memory proof2 = new bytes32[](0);

        vm.prank(alice);
        token.inscribe(sid2, receipt2, sig2, proof2, 600);

        // Each creator got 1 USDC (fee 2 - protocol 1)
        assertEq(usdc.balanceOf(creator) - creator1Before, 1_000000);
        assertEq(usdc.balanceOf(creator2) - creator2Before, 1_000000);
    }

    // ─── Anchor Tests ───

    function test_anchor() public {
        bytes32 root = keccak256("test_root");
        vm.prank(gateway);
        token.anchor(300, root, 5);
        assertEq(token.anchors(300), root);
    }

    function test_anchorNonGateway_reverts() public {
        vm.prank(alice);
        vm.expectRevert("Not a registered gateway");
        token.anchor(300, keccak256("test"), 5);
    }

    function test_anchorDuplicate_reverts() public {
        vm.startPrank(gateway);
        token.anchor(300, keccak256("root1"), 5);
        vm.expectRevert("Period already anchored");
        token.anchor(300, keccak256("root2"), 3);
        vm.stopPrank();
    }

    function test_anchorNotAligned_reverts() public {
        vm.prank(gateway);
        vm.expectRevert("Period not aligned to interval");
        token.anchor(301, keccak256("root"), 5);
    }

    // ─── Gateway Management Tests ───

    function test_revokeGateway() public {
        token.revokeGateway(gateway);

        uint256 sid = _createTestSeries();
        bytes memory receipt = _makeReceipt(alice, "claude-4.6", 50000, 12345);
        bytes memory sig = _signReceipt(receipt);

        address newGateway = address(0x999);
        token.registerGateway(newGateway);

        bytes32 receiptHash = keccak256(receipt);
        vm.prank(newGateway);
        token.anchor(300, receiptHash, 1);

        bytes32[] memory proof = new bytes32[](0);

        vm.startPrank(alice);
        usdc.approve(address(token), 1_000000);
        vm.expectRevert("Invalid gateway signature");
        token.inscribe(sid, receipt, sig, proof, 300);
        vm.stopPrank();
    }

    // ─── Pause Tests ───

    function test_pauseBlocksDeploy() public {
        token.pause();
        vm.startPrank(creator);
        usdc.approve(address(token), 5_000000);
        vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
        token.deploy("Paused", "claude-4.6", 100, 10000, Token20.SeriesMode.OPEN, 1_000000);
        vm.stopPrank();
    }

    function test_pauseBlocksInscribe() public {
        uint256 sid = _createTestSeries();
        bytes memory receipt = _makeReceipt(alice, "claude-4.6", 50000, 12345);
        bytes memory sig = _signReceipt(receipt);
        (bytes32[] memory proof, uint256 period) = _anchorAndGetProof(receipt);

        token.pause();

        vm.startPrank(alice);
        usdc.approve(address(token), 1_000000);
        vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
        token.inscribe(sid, receipt, sig, proof, period);
        vm.stopPrank();
    }

    function test_unpauseResumes() public {
        uint256 sid = _createTestSeries();
        token.pause();
        token.unpause();

        bytes memory receipt = _makeReceipt(alice, "claude-4.6", 50000, 12345);
        bytes memory sig = _signReceipt(receipt);
        (bytes32[] memory proof, uint256 period) = _anchorAndGetProof(receipt);

        vm.startPrank(alice);
        usdc.approve(address(token), 1_000000);
        token.inscribe(sid, receipt, sig, proof, period);
        vm.stopPrank();

        assertEq(token.ownerOf(1), alice);
    }

    // ─── Verify Tests ───

    function test_verify() public {
        _createTestSeries();
        bytes memory receipt = _makeReceipt(alice, "claude-4.6", 50000, 12345);
        bytes memory sig = _signReceipt(receipt);
        (bytes32[] memory proof, uint256 period) = _anchorAndGetProof(receipt);

        (bool valid, uint256 remaining) = token.verify(receipt, sig, proof, period);
        assertTrue(valid);
        assertEq(remaining, 50000);
    }

    // ─── Token URI Tests ���──

    function test_tokenURI() public {
        uint256 sid = _createTestSeries();
        bytes memory receipt = _makeReceipt(alice, "claude-4.6", 11700, 12345678);
        bytes memory sig = _signReceipt(receipt);
        (bytes32[] memory proof, uint256 period) = _anchorAndGetProof(receipt);

        vm.startPrank(alice);
        usdc.approve(address(token), 1_000000);
        token.inscribe(sid, receipt, sig, proof, period);
        vm.stopPrank();

        string memory uri = token.tokenURI(1);
        assertTrue(bytes(uri).length > 0);
        assertTrue(_startsWith(uri, "data:application/json;base64,"));
    }

    function _startsWith(string memory str, string memory prefix) internal pure returns (bool) {
        bytes memory strBytes = bytes(str);
        bytes memory prefixBytes = bytes(prefix);
        if (strBytes.length < prefixBytes.length) return false;
        for (uint i = 0; i < prefixBytes.length; i++) {
            if (strBytes[i] != prefixBytes[i]) return false;
        }
        return true;
    }

    // ─── Series Full Mint Tests ───

    function test_seriesFullyMinted_reverts() public {
        vm.startPrank(creator);
        usdc.approve(address(token), 5_000000);
        uint256 sid = token.deploy("Tiny", "claude-4.6", 2, 10000, Token20.SeriesMode.OPEN, 1_000000);
        vm.stopPrank();

        bytes memory receipt = _makeReceipt(alice, "claude-4.6", 50000, 12345);
        bytes memory sig = _signReceipt(receipt);
        (bytes32[] memory proof, uint256 period) = _anchorAndGetProof(receipt);

        vm.startPrank(alice);
        usdc.approve(address(token), 3_000000);
        token.inscribe(sid, receipt, sig, proof, period);
        token.inscribe(sid, receipt, sig, proof, period);

        vm.expectRevert("Series fully minted");
        token.inscribe(sid, receipt, sig, proof, period);
        vm.stopPrank();
    }

    // ─── Admin Tests ───

    function test_setTreasury() public {
        address newTreasury = address(0xBEEF);
        token.setTreasury(newTreasury);
        assertEq(token.treasury(), newTreasury);
    }

    function test_setTreasuryZero_reverts() public {
        vm.expectRevert("Treasury cannot be zero");
        token.setTreasury(address(0));
    }

    function test_setTreasuryNonOwner_reverts() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", alice));
        token.setTreasury(alice);
    }

    function test_setDeployFee() public {
        token.setDeployFee(10_000000);
        assertEq(token.deployFee(), 10_000000);
    }

    function test_setMinInscriptionFee() public {
        token.setMinInscriptionFee(2_000000);
        assertEq(token.minInscriptionFee(), 2_000000);
    }

    function test_setMinInscriptionFeeBelowProtocol_reverts() public {
        vm.expectRevert("Below protocol fee");
        token.setMinInscriptionFee(500000);
    }

    function test_setAnchorInterval() public {
        token.setAnchorInterval(600);
        assertEq(token.anchorInterval(), 600);
    }

    // ─── Authorization Events Tests ──��

    function test_authorizeEmitsEvent() public {
        vm.startPrank(creator);
        usdc.approve(address(token), 5_000000);
        uint256 sid = token.deploy("EventTest", "claude-4.6", 100, 10000, Token20.SeriesMode.RESTRICTED, 1_000000);

        vm.expectEmit(true, true, false, false);
        emit Token20.Authorized(sid, alice);
        token.authorize(sid, alice);
        vm.stopPrank();
    }

    function test_revokeAuthEmitsEvent() public {
        vm.startPrank(creator);
        usdc.approve(address(token), 5_000000);
        uint256 sid = token.deploy("RevokeTest", "claude-4.6", 100, 10000, Token20.SeriesMode.RESTRICTED, 1_000000);
        token.authorize(sid, alice);

        vm.expectEmit(true, true, false, false);
        emit Token20.AuthRevoked(sid, alice);
        token.revokeAuth(sid, alice);
        vm.stopPrank();
    }

    function test_authorizeBatchLimit() public {
        vm.startPrank(creator);
        usdc.approve(address(token), 5_000000);
        uint256 sid = token.deploy("BatchTest", "claude-4.6", 100, 10000, Token20.SeriesMode.RESTRICTED, 1_000000);

        address[] memory addrs = new address[](101);
        for (uint i = 0; i < 101; i++) {
            addrs[i] = address(uint160(i + 1));
        }
        vm.expectRevert("Batch too large");
        token.authorizeBatch(sid, addrs);
        vm.stopPrank();
    }

    // ─── Boundary Tests ───

    function test_maxSupplyOne() public {
        vm.startPrank(creator);
        usdc.approve(address(token), 5_000000);
        uint256 sid = token.deploy("SingleMint", "claude-4.6", 1, 10000, Token20.SeriesMode.OPEN, 1_000000);
        vm.stopPrank();

        bytes memory receipt = _makeReceipt(alice, "claude-4.6", 50000, 12345);
        bytes memory sig = _signReceipt(receipt);
        (bytes32[] memory proof, uint256 period) = _anchorAndGetProof(receipt);

        vm.startPrank(alice);
        usdc.approve(address(token), 2_000000);
        token.inscribe(sid, receipt, sig, proof, period);

        vm.expectRevert("Series fully minted");
        token.inscribe(sid, receipt, sig, proof, period);
        vm.stopPrank();

        assertEq(token.ownerOf(1), alice);
    }

    function test_thresholdEqualsTokens() public {
        vm.startPrank(creator);
        usdc.approve(address(token), 5_000000);
        uint256 sid = token.deploy("ExactFit", "claude-4.6", 100, 50000, Token20.SeriesMode.OPEN, 1_000000);
        vm.stopPrank();

        bytes memory receipt = _makeReceipt(alice, "claude-4.6", 50000, 12345);
        bytes memory sig = _signReceipt(receipt);
        (bytes32[] memory proof, uint256 period) = _anchorAndGetProof(receipt);

        vm.startPrank(alice);
        usdc.approve(address(token), 2_000000);
        token.inscribe(sid, receipt, sig, proof, period);
        assertEq(token.ownerOf(1), alice);

        vm.expectRevert("Insufficient receipt balance");
        token.inscribe(sid, receipt, sig, proof, period);
        vm.stopPrank();
    }

    function test_pauseDoesNotBlockAnchor() public {
        token.pause();
        vm.prank(gateway);
        token.anchor(300, keccak256("root"), 5);
        assertEq(token.anchors(300), keccak256("root"));
    }

    function test_setAnchorIntervalZero_reverts() public {
        vm.expectRevert("Interval must be > 0");
        token.setAnchorInterval(0);
    }

    function test_invalidateAnchor() public {
        vm.prank(gateway);
        token.anchor(300, keccak256("root"), 5);
        assertEq(token.anchors(300), keccak256("root"));

        token.invalidateAnchor(300);
        assertEq(token.anchors(300), bytes32(0));
    }

    function test_invalidateAnchorNonOwner_reverts() public {
        vm.prank(gateway);
        token.anchor(300, keccak256("root"), 5);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", alice));
        token.invalidateAnchor(300);
    }

    function test_invalidateAnchorNotAnchored_reverts() public {
        vm.expectRevert("Period not anchored");
        token.invalidateAnchor(300);
    }

    function test_anchorTooOld_reverts() public {
        vm.prank(gateway);
        token.anchor(0, keccak256("root"), 5);

        token.setMaxAnchorAge(100);

        vm.prank(gateway);
        vm.expectRevert("Period too old");
        token.anchor(300, keccak256("root2"), 5);
    }

    function test_setMaxAnchorAge() public {
        token.setMaxAnchorAge(100);
        assertEq(token.maxAnchorAge(), 100);
    }

    function test_setMaxAnchorAgeZero_reverts() public {
        vm.expectRevert("Age must be > 0");
        token.setMaxAnchorAge(0);
    }

    // ─── JSON Injection Tests ───

    function test_deployUnsafeName_reverts() public {
        vm.startPrank(creator);
        usdc.approve(address(token), 5_000000);
        vm.expectRevert("Name: unsafe characters");
        token.deploy('Bad"Name', "claude-4.6", 100, 10000, Token20.SeriesMode.OPEN, 1_000000);
        vm.stopPrank();
    }

    function test_inscribeUnsafeModel_reverts() public {
        uint256 sid = _createTestSeries();
        bytes memory receipt = _makeReceipt(alice, 'claude","evil":"true', 50000, 12345);
        bytes memory sig = _signReceipt(receipt);
        (bytes32[] memory proof, uint256 period) = _anchorAndGetProof(receipt);

        vm.startPrank(alice);
        usdc.approve(address(token), 1_000000);
        vm.expectRevert("Model: unsafe characters");
        token.inscribe(sid, receipt, sig, proof, period);
        vm.stopPrank();
    }

    // ─── Nonexistent Series Tests ───

    function test_inscribeNonexistentSeries_reverts() public {
        bytes memory receipt = _makeReceipt(alice, "claude-4.6", 50000, 12345);
        bytes memory sig = _signReceipt(receipt);
        (bytes32[] memory proof, uint256 period) = _anchorAndGetProof(receipt);

        vm.startPrank(alice);
        usdc.approve(address(token), 1_000000);
        vm.expectRevert();
        token.inscribe(999, receipt, sig, proof, period);
        vm.stopPrank();
    }

    function test_inscribeEmptyModel_reverts() public {
        vm.startPrank(creator);
        usdc.approve(address(token), 5_000000);
        uint256 sid = token.deploy("WildCard2", "", 100, 10000, Token20.SeriesMode.OPEN, 1_000000);
        vm.stopPrank();

        bytes memory receipt = _makeReceipt(alice, "", 50000, 12345);
        bytes memory sig = _signReceipt(receipt);
        (bytes32[] memory proof, uint256 period) = _anchorAndGetProof(receipt);

        vm.startPrank(alice);
        usdc.approve(address(token), 1_000000);
        vm.expectRevert("Empty model");
        token.inscribe(sid, receipt, sig, proof, period);
        vm.stopPrank();
    }

    function test_renounceOwnership_reverts() public {
        vm.expectRevert("Disabled");
        token.renounceOwnership();
    }

    // ─── Zero Balance Invariant ───

    function test_contractHoldsZeroAfterOperations() public {
        // Deploy + inscribe + inscribe = contract should always be at zero
        vm.startPrank(creator);
        usdc.approve(address(token), 5_000000);
        uint256 sid = token.deploy("ZeroTest", "claude-4.6", 100, 10000, Token20.SeriesMode.OPEN, 2_000000);
        vm.stopPrank();
        assertEq(usdc.balanceOf(address(token)), 0);

        bytes memory receipt = _makeReceipt(alice, "claude-4.6", 50000, 12345);
        bytes memory sig = _signReceipt(receipt);
        (bytes32[] memory proof, uint256 period) = _anchorAndGetProof(receipt);

        vm.startPrank(alice);
        usdc.approve(address(token), 10_000000);
        token.inscribe(sid, receipt, sig, proof, period);
        assertEq(usdc.balanceOf(address(token)), 0);

        token.inscribe(sid, receipt, sig, proof, period);
        assertEq(usdc.balanceOf(address(token)), 0);
        vm.stopPrank();
    }
}
