// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/token/ERC721/ERC721Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/Base64.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @notice Minimal EIP-3009 interface (USDC)
interface IERC20WithAuth {
    function transfer(address to, uint256 value) external returns (bool);
    function transferFrom(address from, address to, uint256 value) external returns (bool);
    function transferWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;
    function balanceOf(address account) external view returns (uint256);
}

/// @title Token20 — Verifiable AI compute inscriptions on Base
/// @notice ERC-721 NFTs representing proven AI token consumption.
///         Push-model fees: USDC goes directly to treasury and creator during inscribe.
///         Contract holds zero USDC. UUPS upgradeable with timelock governance.
contract Token20 is ERC721Upgradeable, OwnableUpgradeable, PausableUpgradeable, UUPSUpgradeable {
    using Strings for uint256;
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    // ─── Enums & Structs ───

    enum SeriesMode { OPEN, RESTRICTED }

    struct Series {
        string name;
        string modelId;
        bytes32 modelIdHash;
        uint256 maxSupply;
        uint256 mintThreshold;
        SeriesMode mode;
        address creator;
        uint256 inscriptionFee;
        uint256 minted;
    }

    struct Receipt {
        address wallet;
        string model;
        uint256 tokens;
        uint256 blockNumber;
    }

    struct Inscription {
        uint256 seriesId;
        address wallet;
        string model;
        uint256 tokens;
        uint256 blockNumber;
        address gateway;
    }

    // ─── State (storage layout is fixed — append only, never reorder) ───

    IERC20WithAuth public usdc;
    address public treasury;

    uint256 public deployFee;
    uint256 public minInscriptionFee;
    uint256 public constant PROTOCOL_FEE = 1_000000;     // 1 USDC fixed
    uint256 public anchorInterval;
    uint256 public maxAnchorAge;

    uint256 private _nextTokenId;
    uint256 private _nextSeriesId;

    mapping(uint256 => Series) public series;
    mapping(bytes32 => bool) public nameExists;
    mapping(bytes32 => uint256) public receiptUsed;
    mapping(uint256 => Inscription) public inscriptions;
    mapping(address => bool) public gateways;
    mapping(uint256 => mapping(address => bool)) public authorized;

    // Anchor state
    mapping(uint256 => bytes32) public anchors;

    // ─── Events ───

    event SeriesCreated(
        uint256 indexed seriesId,
        string name,
        string modelId,
        address indexed creator,
        SeriesMode mode,
        uint256 maxSupply,
        uint256 mintThreshold,
        uint256 inscriptionFee
    );

    event Inscribe(
        uint256 indexed tokenId,
        address indexed wallet,
        uint256 indexed seriesId,
        string model,
        uint256 tokens,
        uint256 blockNumber,
        address gateway,
        uint256 fee,
        address submitter
    );

    event Anchor(
        uint256 indexed periodStart,
        bytes32 merkleRoot,
        uint256 receiptCount,
        address indexed gateway
    );

    event GatewayRegistered(address indexed gateway);
    event GatewayRevoked(address indexed gateway);
    event Authorized(uint256 indexed seriesId, address indexed addr);
    event AuthRevoked(uint256 indexed seriesId, address indexed addr);
    event AdminParamChanged(string param, uint256 value);
    event AnchorInvalidated(uint256 indexed periodStart);
    event TreasuryChanged(address indexed oldTreasury, address indexed newTreasury);
    event CreatorPaymentFallback(address indexed creator, uint256 amount, uint256 indexed seriesId);

    // ─── Initializer (replaces constructor for proxy pattern) ───

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address _usdc, address _treasury, address _owner) external initializer {
        require(_treasury != address(0), "Treasury cannot be zero");
        require(_usdc != address(0), "USDC cannot be zero");

        __ERC721_init("Token20", "T20");
        __Ownable_init(_owner);
        __Pausable_init();
        __UUPSUpgradeable_init();

        usdc = IERC20WithAuth(_usdc);
        treasury = _treasury;
        deployFee = 5_000000;
        minInscriptionFee = 1_000000;
        anchorInterval = 300;
        maxAnchorAge = 43200;
        _nextTokenId = 1;
        _nextSeriesId = 1;
    }

    // ─── UUPS Authorization ───

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    // ─── Deploy Series ───

    function deploy(
        string calldata name,
        string calldata modelId,
        uint256 maxSupply,
        uint256 mintThreshold,
        SeriesMode mode,
        uint256 inscriptionFee
    ) external whenNotPaused returns (uint256 seriesId) {
        require(usdc.transferFrom(msg.sender, treasury, deployFee), "USDC transfer failed");
        seriesId = _createSeries(name, modelId, maxSupply, mintThreshold, mode, inscriptionFee, msg.sender);
    }

    function deployWithAuth(
        string calldata name,
        string calldata modelId,
        uint256 maxSupply,
        uint256 mintThreshold,
        SeriesMode mode,
        uint256 inscriptionFee,
        address from,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external whenNotPaused returns (uint256 seriesId) {
        require(value == deployFee, "Value must equal deploy fee");
        usdc.transferWithAuthorization(from, treasury, value, validAfter, validBefore, nonce, v, r, s);
        seriesId = _createSeries(name, modelId, maxSupply, mintThreshold, mode, inscriptionFee, from);
    }

    function _createSeries(
        string calldata name,
        string calldata modelId,
        uint256 maxSupply,
        uint256 mintThreshold,
        SeriesMode mode,
        uint256 inscriptionFee,
        address creator
    ) internal returns (uint256 seriesId) {
        bytes memory nameBytes = bytes(name);
        require(nameBytes.length >= 1 && nameBytes.length <= 32, "Name: 1-32 bytes");
        require(_isSafeString(name), "Name: unsafe characters");
        bytes32 nameHash = keccak256(nameBytes);
        require(!nameExists[nameHash], "Name taken");
        if (bytes(modelId).length > 0) {
            require(bytes(modelId).length <= 64, "ModelId: too long");
            require(_isSafeString(modelId), "ModelId: unsafe characters");
        }
        require(maxSupply > 0, "maxSupply must be > 0");
        require(mintThreshold > 0, "mintThreshold must be > 0");
        require(inscriptionFee >= minInscriptionFee, "Fee below minimum");

        nameExists[nameHash] = true;
        seriesId = _nextSeriesId++;
        series[seriesId] = Series({
            name: name,
            modelId: modelId,
            modelIdHash: bytes(modelId).length > 0 ? keccak256(bytes(modelId)) : bytes32(0),
            maxSupply: maxSupply,
            mintThreshold: mintThreshold,
            mode: mode,
            creator: creator,
            inscriptionFee: inscriptionFee,
            minted: 0
        });

        emit SeriesCreated(seriesId, name, modelId, creator, mode, maxSupply, mintThreshold, inscriptionFee);
    }

    // ─── Inscribe ───

    function inscribe(
        uint256 seriesId,
        bytes calldata receipt,
        bytes calldata signature,
        bytes32[] calldata merkleProof,
        uint256 periodStart
    ) external whenNotPaused {
        Series storage s = series[seriesId];
        uint256 fee = s.inscriptionFee;

        require(usdc.transferFrom(msg.sender, treasury, PROTOCOL_FEE), "USDC transfer failed");

        if (fee > PROTOCOL_FEE) {
            _payCreator(msg.sender, s.creator, fee - PROTOCOL_FEE, seriesId);
        }

        Receipt memory r = _decodeReceipt(receipt);
        _inscribe(seriesId, receipt, r, signature, merkleProof, periodStart, fee);
    }

    function inscribeWithAuth(
        uint256 seriesId,
        bytes calldata receipt,
        bytes calldata signature,
        bytes32[] calldata merkleProof,
        uint256 periodStart,
        address from,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 rAuth,
        bytes32 sAuth
    ) external whenNotPaused {
        Series storage s = series[seriesId];
        uint256 fee = s.inscriptionFee;
        require(value == fee, "Value must equal inscription fee");

        usdc.transferWithAuthorization(from, address(this), value, validAfter, validBefore, nonce, v, rAuth, sAuth);

        require(usdc.transfer(treasury, PROTOCOL_FEE), "Treasury transfer failed");
        if (fee > PROTOCOL_FEE) {
            uint256 creatorShare = fee - PROTOCOL_FEE;
            if (!usdc.transfer(s.creator, creatorShare)) {
                require(usdc.transfer(treasury, creatorShare), "Fallback transfer failed");
                emit CreatorPaymentFallback(s.creator, creatorShare, seriesId);
            }
        }

        Receipt memory r = _decodeReceipt(receipt);
        _inscribe(seriesId, receipt, r, signature, merkleProof, periodStart, fee);
    }

    function _payCreator(address payer, address creator, uint256 amount, uint256 seriesId) internal {
        if (!usdc.transferFrom(payer, creator, amount)) {
            require(usdc.transferFrom(payer, treasury, amount), "Fallback transfer failed");
            emit CreatorPaymentFallback(creator, amount, seriesId);
        }
    }

    function _inscribe(
        uint256 seriesId,
        bytes calldata receiptBytes,
        Receipt memory r,
        bytes calldata signature,
        bytes32[] calldata merkleProof,
        uint256 periodStart,
        uint256 fee
    ) internal {
        Series storage s = series[seriesId];
        require(s.maxSupply > 0, "Series does not exist");
        require(s.minted < s.maxSupply, "Series fully minted");

        require(bytes(r.model).length > 0, "Empty model");
        require(_isSafeString(r.model), "Model: unsafe characters");
        if (s.modelIdHash != bytes32(0)) {
            require(keccak256(bytes(r.model)) == s.modelIdHash, "Model mismatch");
        }

        require(msg.sender == r.wallet, "Not receipt owner");

        if (s.mode == SeriesMode.RESTRICTED) {
            require(authorized[seriesId][r.wallet], "Not authorized");
        }

        bytes32 receiptHash = keccak256(receiptBytes);
        address signer = receiptHash.toEthSignedMessageHash().recover(signature);
        require(gateways[signer], "Invalid gateway signature");

        bytes32 root = anchors[periodStart];
        require(root != bytes32(0), "Period not anchored");
        require(MerkleProof.verify(merkleProof, root, receiptHash), "Invalid Merkle proof");

        uint256 used = receiptUsed[receiptHash];
        require(r.tokens >= used + s.mintThreshold, "Insufficient receipt balance");

        receiptUsed[receiptHash] = used + s.mintThreshold;
        uint256 tokenId = _nextTokenId++;
        s.minted++;

        _mint(r.wallet, tokenId);

        inscriptions[tokenId] = Inscription({
            seriesId: seriesId,
            wallet: r.wallet,
            model: r.model,
            tokens: r.tokens,
            blockNumber: r.blockNumber,
            gateway: signer
        });

        emit Inscribe(tokenId, r.wallet, seriesId, r.model, r.tokens, r.blockNumber, signer, fee, msg.sender);
    }

    // ─── Verify ───

    function verify(
        bytes calldata receipt,
        bytes calldata signature,
        bytes32[] calldata merkleProof,
        uint256 periodStart
    ) external view returns (bool valid, uint256 remaining) {
        bytes32 receiptHash = keccak256(receipt);
        address signer = receiptHash.toEthSignedMessageHash().recover(signature);
        if (!gateways[signer]) return (false, 0);

        bytes32 root = anchors[periodStart];
        if (root == bytes32(0)) return (false, 0);
        if (!MerkleProof.verify(merkleProof, root, receiptHash)) return (false, 0);

        Receipt memory r = _decodeReceipt(receipt);
        uint256 used = receiptUsed[receiptHash];
        if (r.tokens <= used) return (true, 0);
        return (true, r.tokens - used);
    }

    // ─── Anchor ───

    function anchor(uint256 periodStart, bytes32 merkleRoot, uint256 receiptCount) external {
        require(gateways[msg.sender], "Not a registered gateway");
        require(periodStart % anchorInterval == 0, "Period not aligned to interval");
        require(periodStart <= block.number, "Future period");
        require(block.number - periodStart <= maxAnchorAge, "Period too old");
        require(anchors[periodStart] == bytes32(0), "Period already anchored");
        require(merkleRoot != bytes32(0), "Empty root");

        anchors[periodStart] = merkleRoot;
        emit Anchor(periodStart, merkleRoot, receiptCount, msg.sender);
    }

    function invalidateAnchor(uint256 periodStart) external onlyOwner {
        require(anchors[periodStart] != bytes32(0), "Period not anchored");
        anchors[periodStart] = bytes32(0);
        emit AnchorInvalidated(periodStart);
    }

    // ─── Series Authorization ───

    function authorize(uint256 seriesId, address addr) external {
        require(msg.sender == series[seriesId].creator, "Not series creator");
        authorized[seriesId][addr] = true;
        emit Authorized(seriesId, addr);
    }

    function authorizeBatch(uint256 seriesId, address[] calldata addrs) external {
        require(msg.sender == series[seriesId].creator, "Not series creator");
        require(addrs.length <= 100, "Batch too large");
        for (uint256 i = 0; i < addrs.length; i++) {
            authorized[seriesId][addrs[i]] = true;
            emit Authorized(seriesId, addrs[i]);
        }
    }

    function revokeAuth(uint256 seriesId, address addr) external {
        require(msg.sender == series[seriesId].creator, "Not series creator");
        authorized[seriesId][addr] = false;
        emit AuthRevoked(seriesId, addr);
    }

    // ─── Gateway Management ───

    function registerGateway(address gateway) external onlyOwner {
        gateways[gateway] = true;
        emit GatewayRegistered(gateway);
    }

    function revokeGateway(address gateway) external onlyOwner {
        gateways[gateway] = false;
        emit GatewayRevoked(gateway);
    }

    // ─── Admin ───

    function renounceOwnership() public pure override {
        revert("Disabled");
    }

    function pause() external onlyOwner { _pause(); }
    function unpause() external onlyOwner { _unpause(); }

    function setTreasury(address _treasury) external onlyOwner {
        require(_treasury != address(0), "Treasury cannot be zero");
        address old = treasury;
        treasury = _treasury;
        emit TreasuryChanged(old, _treasury);
    }

    function setDeployFee(uint256 fee) external onlyOwner {
        deployFee = fee;
        emit AdminParamChanged("deployFee", fee);
    }
    function setMinInscriptionFee(uint256 fee) external onlyOwner {
        require(fee >= PROTOCOL_FEE, "Below protocol fee");
        minInscriptionFee = fee;
        emit AdminParamChanged("minInscriptionFee", fee);
    }
    function setAnchorInterval(uint256 blocks) external onlyOwner {
        require(blocks > 0, "Interval must be > 0");
        anchorInterval = blocks;
        emit AdminParamChanged("anchorInterval", blocks);
    }
    function setMaxAnchorAge(uint256 blocks) external onlyOwner {
        require(blocks > 0, "Age must be > 0");
        maxAnchorAge = blocks;
        emit AdminParamChanged("maxAnchorAge", blocks);
    }

    // ─── Token URI (on-chain metadata) ───

    function tokenURI(uint256 tokenId) public view override returns (string memory) {
        _requireOwned(tokenId);
        Inscription memory ins = inscriptions[tokenId];
        Series memory s = series[ins.seriesId];

        string memory json = string(abi.encodePacked(
            '{"name":"token-20 #', tokenId.toString(),
            '","description":"AI compute proof: ', ins.tokens.toString(),
            ' tokens on ', ins.model,
            '","attributes":[',
            '{"trait_type":"Series","value":"', s.name, '"},',
            '{"trait_type":"Model","value":"', ins.model, '"},',
            '{"trait_type":"Tokens","display_type":"number","value":', ins.tokens.toString(), '},',
            '{"trait_type":"Block","display_type":"number","value":', ins.blockNumber.toString(), '},',
            '{"trait_type":"Gateway","value":"', Strings.toHexString(ins.gateway), '"}',
            ']}'
        ));

        return string(abi.encodePacked(
            "data:application/json;base64,",
            Base64.encode(bytes(json))
        ));
    }

    // ─── Internal Helpers ───

    function _decodeReceipt(bytes calldata receipt) internal pure returns (Receipt memory) {
        return abi.decode(receipt, (Receipt));
    }

    function _isSafeString(string memory s) internal pure returns (bool) {
        bytes memory b = bytes(s);
        for (uint256 i = 0; i < b.length; i++) {
            bytes1 c = b[i];
            if (
                !(c >= 0x30 && c <= 0x39) && // 0-9
                !(c >= 0x41 && c <= 0x5A) && // A-Z
                !(c >= 0x61 && c <= 0x7A) && // a-z
                c != 0x2D && // -
                c != 0x2E && // .
                c != 0x2F && // /
                c != 0x5F && // _
                c != 0x20    // space
            ) {
                return false;
            }
        }
        return true;
    }
}
