// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

/**
 * @title RcadeAirDrop
 * @dev Contract for distributing native currency airdrops using Merkle proofs.
 * Implements UUPS upgradeable pattern with access control and pausable functionality.
 */
contract RcadeAirDrop is
    Initializable,
    ReentrancyGuardUpgradeable,
    AccessControlUpgradeable,
    PausableUpgradeable,
    UUPSUpgradeable,
    OwnableUpgradeable
{
    // Events
    event OwnershipTransferred(
        address indexed previousOwner,
        address indexed newOwner,
        uint256 timestamp,
        address indexed caller
    );
    
    event Claimed(
        address indexed user,
        uint256 amount,
        uint256 totalClaimed,
        uint256 timestamp
    );
    
    event MerkleRootUpdated(
        bytes32 indexed oldRoot,
        bytes32 indexed newRoot,
        uint256 timestamp,
        address indexed initiatedBy
    );
    
    event AirdropEndTimeUpdated(
        uint256 indexed oldAirDropEndTime,
        uint256 indexed newAirDropEndTime,
        uint256 timestamp,
        address indexed initiatedBy
    );

    event AirdropFunded(
        uint256 amount,
        uint256 timestamp,
        address indexed initiatedBy
    );
    
    // State Variables
    bytes32 public merkleRoot;
    uint256 public airDropEndTime;
    
    mapping(address => uint256) public userTotalClaimed;

    //Roles
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    bytes32 public constant ADMIN_ROLE = keccak256("DEFAULT_ADMIN_ROLE");
    
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @dev Initializes the contract with admin and merkle root
     * @param admin The address that will have admin privileges
     * @param initialMerkleRoot The initial merkle root for airdrop claims
     * @param _airDropEndTime The timestamp when airdrop ends
     */
    function initialize(
        address admin,
        bytes32 initialMerkleRoot,
        uint256 _airDropEndTime
    ) public initializer {
        __ReentrancyGuard_init();
        __AccessControl_init();
        __Pausable_init();
        __UUPSUpgradeable_init();
        __Ownable_init(msg.sender);

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);
        
        merkleRoot = initialMerkleRoot;
        airDropEndTime = _airDropEndTime;
    }

    /**
     * @dev Claims airdrop allocation using merkle proof
     * @param totalAllocation Total allocated coins for user
     * @param merkleProof The merkle proof for verification
     * Requires valid merkle proof and sufficient contract balance
     */
    function claim(
        uint256 totalAllocation,
        bytes32[] calldata merkleProof
    ) external nonReentrant whenNotPaused {
        _isAirdropActive();
        _isValidAllocation(totalAllocation);

        uint256 remainingAmount = totalAllocation - userTotalClaimed[msg.sender];
        _hasSufficientBalance(remainingAmount);
        _isValidClaim(totalAllocation, remainingAmount, merkleProof, msg.sender);

        userTotalClaimed[msg.sender] = totalAllocation;
        _transferNative(msg.sender, remainingAmount);

        emit Claimed(msg.sender, remainingAmount, totalAllocation, block.timestamp);
    }

    /**
     * @dev Pauses the contract
     * Only callable by addresses with PAUSER_ROLE
     */
    function pause() public onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /**
     * @dev Unpauses the contract
     * Only callable by addresses with PAUSER_ROLE
     */
    function unpause() public onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    /**
     * @dev Funds the airdrop contract with native currency
     * Only callable by addresses with DEFAULT_ADMIN_ROLE
     */
    function fundAirdrop() external payable onlyRole(DEFAULT_ADMIN_ROLE) {
        _isValidAmount(msg.value);
        emit AirdropFunded(msg.value, block.timestamp, msg.sender);
    }

    /**
     * @dev Withdraws excess funds from the contract
     * Only callable by addresses with DEFAULT_ADMIN_ROLE
     */
    function withdrawExcessFunds() external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(!isAirdropActive(), "AirDrop: Airdrop is still active");
        uint256 balance = address(this).balance;
        _transferNative(msg.sender, balance);
    }

    /**
     * @dev Updates the merkle root for airdrop claims
     * @param newRoot The new merkle root
     * Only callable by addresses with DEFAULT_ADMIN_ROLE
     */
    function updateMerkleRoot(bytes32 newRoot) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _isValidMerkleRoot(newRoot);
        bytes32 oldRoot = merkleRoot;
        merkleRoot = newRoot;
        emit MerkleRootUpdated(oldRoot, newRoot, block.timestamp, msg.sender);
    }

    /**
     * @dev Updates the airdrop end time
     * @param _timestamp The new end time
     * Only callable by addresses with DEFAULT_ADMIN_ROLE
     */
    function updateAirDropEndTime(uint256 _timestamp) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _isValidTimestamp(_timestamp);
        uint256 oldTime = airDropEndTime;
        airDropEndTime = _timestamp;
        emit AirdropEndTimeUpdated(oldTime, _timestamp, block.timestamp, msg.sender);
    }

    /**
     * @dev Returns true if airdrop is active
     */
    function isAirdropActive() public view returns (bool) {
        return block.timestamp <= airDropEndTime;
    }

    /**
     * @dev Validates if airdrop is active
     * Reverts if airdrop has ended
     */
    function _isAirdropActive() internal view {
        require(isAirdropActive(), "AirDrop: Airdrop has ended");
    }

    /**
     * @dev Validates timestamp
     * @param _timestamp The timestamp to validate
     * Reverts if timestamp is invalid
     */
    function _isValidTimestamp(uint256 _timestamp) internal view {
        require(_timestamp > block.timestamp && _timestamp != 0, "AirDrop: Invalid timestamp");
    }

    /**
     * @dev Validates merkle root
     * @param root The merkle root to validate
     * Reverts if merkle root is zero
     */
    function _isValidMerkleRoot(bytes32 root) internal pure {
        require(root != bytes32(0), "AirDrop: Invalid merkle root");
    }

    /**
     * @dev Validates allocation
     * @param totalAllocation The total allocation to validate
     * Reverts if allocation is invalid
     */
    function _isValidAllocation(uint256 totalAllocation) internal view {
        require(totalAllocation >= userTotalClaimed[msg.sender], "AirDrop: Invalid total allocation");
    }

    /**
     * @dev Validates claim parameters and merkle proof
     * @param totalAllocation Total allocated coins for user
     * @param remainingAmount Remaining coins to claim
     * @param merkleProof Merkle proof for verification
     * @param claimer Address of the claimer
     * Reverts if merkle proof is invalid or no coins left to claim
     */
    function _isValidClaim(
        uint256 totalAllocation,
        uint256 remainingAmount,
        bytes32[] calldata merkleProof,
        address claimer
    ) internal view {
        bytes32 leaf = keccak256(
            bytes.concat(keccak256(abi.encode(claimer, totalAllocation)))
        );
        require(
            MerkleProof.verify(merkleProof, merkleRoot, leaf),
            "AirDrop: Invalid merkle proof"
        );

        require(remainingAmount > 0, "AirDrop: No coins left to claim");
    }

    /**
     * @dev Validates if an address is valid
     * @param addr The address to validate
     * Reverts if address is zero
     */
    function _isValidAddress(address addr) internal pure {
        require(addr != address(0), "AirDrop: Invalid address");
    }

    /**
     * @dev Validates if amount is greater than zero
     * @param amount The amount to validate
     * Reverts if amount is zero
     */
    function _isValidAmount(uint256 amount) internal pure {
        require(amount > 0, "AirDrop: Invalid amount");
    }

    /**
     * @dev Validates if contract has sufficient balance
     * @param amount The amount to check
     * Reverts if insufficient balance
     */
    function _hasSufficientBalance(uint256 amount) internal view {
        require(amount <= address(this).balance, "AirDrop: Insufficient airdrop balance");
    }

    /**
     * @dev Transfers native currency
     * @param to The recipient address
     * @param amount The amount to transfer
     * Reverts if transfer fails
     */
    function _transferNative(address to, uint256 amount) internal {
        (bool success, ) = to.call{value: amount}("");
        require(success, "AirDrop: Transfer failed");
    }

    /**
     * @dev Transfers contract ownership and roles to a new address
     * @param newOwner The address to transfer ownership to
     * Only callable by addresses with DEFAULT_ADMIN_ROLE
     */
    function transferContractOwnership(
        address newOwner
    ) public onlyRole(DEFAULT_ADMIN_ROLE) {
        _isValidAddress(newOwner);

        address oldOwner = msg.sender;

        _revokeRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _revokeRole(PAUSER_ROLE, msg.sender);
        _revokeRole(UPGRADER_ROLE, msg.sender);

        _grantRole(DEFAULT_ADMIN_ROLE, newOwner);
        _grantRole(PAUSER_ROLE, newOwner);
        _grantRole(UPGRADER_ROLE, newOwner);

        emit OwnershipTransferred(
            oldOwner,
            newOwner,
            block.timestamp,
            msg.sender
        );
    }

    /**
     * @dev Function that should revert when `msg.sender` is not authorized to upgrade the contract.
     * Called by {upgradeTo} and {upgradeToAndCall}.
     * 
     * Reverts if called by any account other than the owner.
     */
    function _authorizeUpgrade(address newImplementation) 
        internal 
        override 
        onlyOwner 
    {}

    /**
     * @dev Function to receive ETH
     */
    receive() external payable {}
}
