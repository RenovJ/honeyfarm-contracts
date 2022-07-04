/**
 *Submitted for verification at snowtrace.io on 2021-11-03
*/

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/token/ERC20/SafeERC20.sol";

interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address recipient, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
}

interface MintableToken is IERC20 {
    function mint(address dest, uint256 amount) external;
    function transferOwnership(address _minterAddress) external;
}

interface IHoneycombStrategy {
    function deposit(address caller, address to, uint256 tokenAmount, uint256 shareAmount) external;
    function withdraw(address caller, address to, uint256 tokenAmount, uint256 shareAmount) external;
    function inCaseTokensGetStuck(IERC20 token, address to, uint256 amount) external;
    function setAllowances() external;
    function revokeAllowance(address token, address spender) external;
    function migrate(address newStrategy) external;
    function onMigration() external;
    function pendingTokens(uint256 pid, address user, uint256 amount) external view returns (address[] memory, uint256[] memory);
    function transferOwnership(address newOwner) external;
    function setPerformanceFeeBips(uint256 newPerformanceFeeBips) external;
}

interface IStakingRewards {
    function userInfo(uint256, address) external view returns (uint256, uint256);
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function lastTimeRewardApplicable() external view returns (uint256);
    function rewardPerToken() external view returns (uint256);
    function earned(address account) external view returns (uint256);
    function getRewardForDuration() external view returns (uint256);
    function deposit(uint256 pid, uint256 amount) external;
    function withdraw(uint256 pid, uint256 amount) external;
    function stakeWithPermit(uint256 amount, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external;
    function withdraw(uint256 amount) external;
    function getReward() external;
    function pendingCake(uint256 pid, address user) external view returns (uint256);
    function exit() external;
    event RewardAdded(uint256 reward);
    event Staked(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event RewardPaid(address indexed user, uint256 reward);
    event RewardsDurationUpdated(uint256 newDuration);
    event Recovered(address token, uint256 amount);
}

interface IEarningsReferral {
    function recordReferral(address _user, address _referrer) external;
    function recordReferralCommission(address _referrer, uint256 _commission) external;
    function getReferrer(address _user) external view returns (address);
    function updateOperator(address _operator, bool _status) external;
    function drainBEP20Token(IERC20 _token, uint256 _amount, address _to) external;
}

contract HoneycombStrategyBase is IHoneycombStrategy, Ownable {
    using SafeERC20 for IERC20;

    HoneycombMaster public immutable honeycombMaster;
    IERC20 public immutable depositToken;
    uint256 public performanceFeeBips;
    uint256 internal constant MAX_UINT = 115792089237316195423570985008687907853269984665640564039457584007913129639935;
    uint256 internal constant ACC_EARNING_PRECISION = 1e18;
    uint256 internal constant MAX_BIPS = 10000;

    constructor(
        HoneycombMaster _honeycombMaster,
        IERC20 _depositToken
        ){
        honeycombMaster = _honeycombMaster;
        depositToken = _depositToken;
        transferOwnership(address(_honeycombMaster));
    }

    function pendingTokens(uint256, address, uint256) external view virtual override
        returns (address[] memory, uint256[] memory) {
        address[] memory _rewardTokens = new address[](1);
        _rewardTokens[0] = address(0);
        uint256[] memory _pendingAmounts = new uint256[](1);
        _pendingAmounts[0] = 0;
        return(_rewardTokens, _pendingAmounts);
    }

    function deposit(address, address, uint256, uint256) external virtual override onlyOwner {
    }

    function withdraw(address, address to, uint256 tokenAmount, uint256) external virtual override onlyOwner {
        if (tokenAmount > 0) {
            depositToken.safeTransfer(to, tokenAmount);
        }
    }

    function inCaseTokensGetStuck(IERC20 token, address to, uint256 amount) external virtual override onlyOwner {
        require(amount > 0, "cannot recover 0 tokens");
        require(address(token) != address(depositToken), "cannot recover deposit token");
        token.safeTransfer(to, amount);
    }

    function setAllowances() external virtual override onlyOwner {
    }

    function revokeAllowance(address token, address spender) external virtual override onlyOwner {
        IERC20(token).safeApprove(spender, 0);
    }

    function migrate(address newStrategy) external virtual override onlyOwner {
        uint256 toTransfer = depositToken.balanceOf(address(this));
        depositToken.safeTransfer(newStrategy, toTransfer);
    }

    function onMigration() external virtual override onlyOwner {
    }

    function transferOwnership(address newOwner) public virtual override(Ownable, IHoneycombStrategy) onlyOwner {
        Ownable.transferOwnership(newOwner);
    }

    function setPerformanceFeeBips(uint256 newPerformanceFeeBips) external virtual override onlyOwner {
        require(newPerformanceFeeBips <= MAX_BIPS, "input too high");
        performanceFeeBips = newPerformanceFeeBips;
    }
}

contract HoneycombStrategyStorage is Ownable {
    uint256 public rewardTokensPerShare;
    uint256 internal constant ACC_EARNING_PRECISION = 1e18;

    mapping(address => uint256) public rewardDebt;

    function increaseRewardDebt(address user, uint256 shareAmount) external onlyOwner {
        rewardDebt[user] += (rewardTokensPerShare * shareAmount) / ACC_EARNING_PRECISION;
    }

    function decreaseRewardDebt(address user, uint256 shareAmount) external onlyOwner {
        rewardDebt[user] -= (rewardTokensPerShare * shareAmount) / ACC_EARNING_PRECISION;
    }

    function setRewardDebt(address user, uint256 userShares) external onlyOwner {
        rewardDebt[user] = (rewardTokensPerShare * userShares) / ACC_EARNING_PRECISION;
    }

    function increaseRewardTokensPerShare(uint256 amount) external onlyOwner {
        rewardTokensPerShare += amount;
    }
}

contract HoneycombStrategyForPancake is HoneycombStrategyBase {
    using SafeERC20 for IERC20;

    IERC20 public constant rewardToken = IERC20(0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82); //CAKE token
    IStakingRewards public immutable stakingContract;
    HoneycombStrategyStorage public immutable honeycombStrategyStorage;
    uint256 public immutable pid;
    uint256 public immutable pidHoneycomb;
    //total harvested by the contract all time
    uint256 public totalHarvested;
    mapping(address => uint256) public harvested;

    event Harvest(address indexed caller, address indexed to, uint256 harvestedAmount);

    constructor(
        HoneycombMaster _honeycombMaster,
        IERC20 _depositToken,
        uint256 _pid,
        uint256 _pidHoneycomb,
        IStakingRewards _stakingContract,
        HoneycombStrategyStorage _honeycombStrategyStorage
        )
        HoneycombStrategyBase(_honeycombMaster, _depositToken)
    {
        pid = _pid;
        pidHoneycomb = _pidHoneycomb;
        stakingContract = _stakingContract;
        honeycombStrategyStorage = _honeycombStrategyStorage;
        _depositToken.safeApprove(address(_stakingContract), MAX_UINT);
    }

    function checkReward() public view returns (uint256) {
        return stakingContract.pendingCake(pid, address(this));
    }

    function pendingRewards(address user) public view returns (uint256) {
        uint256 userShares = honeycombMaster.userShares(pidHoneycomb, user);
        uint256 unclaimedRewards = checkReward();
        uint256 rewardTokensPerShare = honeycombStrategyStorage.rewardTokensPerShare();
        uint256 totalShares = honeycombMaster.totalShares(pidHoneycomb);
        uint256 userRewardDebt = honeycombStrategyStorage.rewardDebt(user);
        uint256 multiplier =  rewardTokensPerShare;
        if(totalShares > 0) {
            multiplier = multiplier + ((unclaimedRewards * ACC_EARNING_PRECISION) / totalShares);
        }
        uint256 totalRewards = (userShares * multiplier) / ACC_EARNING_PRECISION;
        uint256 userPendingRewards = (totalRewards >= userRewardDebt) ?  (totalRewards - userRewardDebt) : 0;
        return userPendingRewards;
    }

    function rewardTokens() external view virtual returns(address[] memory) {
        address[] memory _rewardTokens = new address[](1);
        _rewardTokens[0] = address(rewardToken);
        return(_rewardTokens);
    }

    function pendingTokens(uint256, address user, uint256) external view override
        returns (address[] memory, uint256[] memory) {
        address[] memory _rewardTokens = new address[](1);
        _rewardTokens[0] = address(rewardToken);
        uint256[] memory _pendingAmounts = new uint256[](1);
        _pendingAmounts[0] = pendingRewards(user);
        return(_rewardTokens, _pendingAmounts);
    }

    function harvest() external {
        _claimRewards();
        _harvest(msg.sender, msg.sender);
    }

    function deposit(address caller, address to, uint256 tokenAmount, uint256 shareAmount) external override onlyOwner {
        _claimRewards();
        _harvest(caller, to);
        if (tokenAmount > 0) {
            stakingContract.deposit(pid, tokenAmount);
        }
        if (shareAmount > 0) {
            honeycombStrategyStorage.increaseRewardDebt(to, shareAmount);
        }
    }

    function withdraw(address caller, address to, uint256 tokenAmount, uint256 shareAmount) external override onlyOwner {
        _claimRewards();
        _harvest(caller, to);
        if (tokenAmount > 0) {
            stakingContract.withdraw(pid, tokenAmount);
            depositToken.safeTransfer(to, tokenAmount);
        }
        if (shareAmount > 0) {
            honeycombStrategyStorage.decreaseRewardDebt(to, shareAmount);
        }
    }

    function migrate(address newStrategy) external override onlyOwner {
        _claimRewards();
        (uint256 toWithdraw, ) = stakingContract.userInfo(pid, address(this));
        if (toWithdraw > 0) {
            stakingContract.withdraw(pid, toWithdraw);
            depositToken.safeTransfer(newStrategy, toWithdraw);
        }
        uint256 rewardsToTransfer = rewardToken.balanceOf(address(this));
        if (rewardsToTransfer > 0) {
            rewardToken.safeTransfer(newStrategy, rewardsToTransfer);
        }
        honeycombStrategyStorage.transferOwnership(newStrategy);
    }

    function onMigration() external override onlyOwner {
        uint256 toStake = depositToken.balanceOf(address(this));
        stakingContract.deposit(pid, toStake);
    }

    function setAllowances() external override onlyOwner {
        depositToken.safeApprove(address(stakingContract), 0);
        depositToken.safeApprove(address(stakingContract), MAX_UINT);
    }

    function _claimRewards() internal {
        uint256 unclaimedRewards = checkReward();
        uint256 totalShares = honeycombMaster.totalShares(pidHoneycomb);
        if (unclaimedRewards > 0 && totalShares > 0) {
            stakingContract.deposit(pid, 0);
            honeycombStrategyStorage.increaseRewardTokensPerShare((unclaimedRewards * ACC_EARNING_PRECISION) / totalShares);
        }
    }

    function _harvest(address caller, address to) internal {
        uint256 userShares = honeycombMaster.userShares(pidHoneycomb, caller);
        uint256 totalRewards = (userShares * honeycombStrategyStorage.rewardTokensPerShare()) / ACC_EARNING_PRECISION;
        uint256 userRewardDebt = honeycombStrategyStorage.rewardDebt(caller);
        uint256 userPendingRewards = (totalRewards >= userRewardDebt) ?  (totalRewards - userRewardDebt) : 0;
        honeycombStrategyStorage.setRewardDebt(caller, userShares);
        if (userPendingRewards > 0) {
            totalHarvested += userPendingRewards;
            if (performanceFeeBips > 0) {
                uint256 performanceFee = (userPendingRewards * performanceFeeBips) / MAX_BIPS;
                _safeRewardTokenTransfer(honeycombMaster.performanceFeeAddress(), performanceFee);
                userPendingRewards = userPendingRewards - performanceFee;
            }
            harvested[to] += userPendingRewards;
            emit Harvest(caller, to, userPendingRewards);
            _safeRewardTokenTransfer(to, userPendingRewards);
        }
    }

    function _safeRewardTokenTransfer(address user, uint256 amount) internal {
        uint256 rewardTokenBal = rewardToken.balanceOf(address(this));
        if (amount > rewardTokenBal) {
            rewardToken.safeTransfer(user, rewardTokenBal);
        } else {
            rewardToken.safeTransfer(user, amount);
        }
    }
}

contract HoneycombMaster is Ownable {
    using SafeERC20 for IERC20;

    struct UserInfo {
        uint256 amount; // How many shares the user currently has
        uint256 rewardDebt; // Reward debt. See explanation below.
        uint256 lastDepositTimestamp; // Timestamp of the last deposit.
    }

    // Info of each pool.
    struct PoolInfo {
        IERC20 want; // Address of LP token contract.
        IHoneycombStrategy strategy; // Address of strategy for pool
        uint256 allocPoint; // How many allocation points assigned to this pool. earnings to distribute per block.
        uint256 lastRewardTime; // Last block number that earnings distribution occurs.
        uint256 accEarningPerShare; // Accumulated earnings per share, times ACC_EARNING_PRECISION. See below.
        uint16 depositFeeBP; // Deposit fee in basis points
        uint256 totalShares; //total number of shares in the pool
        uint256 lpPerShare; //number of LP tokens per share, times ACC_EARNING_PRECISION
        bool isWithdrawFee;      // if the pool has withdraw fee
    }

    MintableToken public immutable earningToken;
    uint256 public startTime;
    address public dev;
    address public performanceFeeAddress;
    uint256 public earningsPerSecond;
    uint256 public totalAllocPoint = 0;
    uint256 public devMintBips = 1000;
    bool public onlyApprovedContractOrEOAStatus;
    uint256 internal constant ACC_EARNING_PRECISION = 1e18;
    uint256 internal constant MAX_BIPS = 10000;

    PoolInfo[] public poolInfo;
    mapping(uint256 => mapping(address => UserInfo)) public userInfo;
    mapping(address => bool) public approvedContracts;
    mapping(uint256 => mapping(address => uint256)) public deposits;
    mapping(uint256 => mapping(address => uint256)) public withdrawals;

    uint256[] public withdrawalFeeIntervals = [1];
    uint16[] public withdrawalFeeBP = [0, 0];
    uint16 public constant MAX_WITHDRAWAL_FEE_BP = 300;
    uint16 public constant MAX_DEPOSIT_FEE_BP = 400;
    
    IEarningsReferral public earningReferral;
    uint16 public referralCommissionRate = 300;
    uint16 public constant MAXIMUM_REFERRAL_COMMISSION_RATE = 2000;

    event Deposit(address indexed user, uint256 indexed pid, uint256 amount, address indexed to);
    event Withdraw(address indexed user, uint256 indexed pid, uint256 amount, address indexed to);
    event EmergencyWithdraw(address indexed user, uint256 indexed pid, uint256 amount, address indexed to);
    event Harvest(address indexed user, uint256 indexed pid, uint256 amount);
    event DevSet(address indexed oldAddress, address indexed newAddress);
    event PerformanceFeeAddressSet(address indexed oldAddress, address indexed newAddress);
    event ReferralCommissionPaid(address indexed user, address indexed referrer, uint256 commissionAmount);

    modifier onlyApprovedContractOrEOA() {
        if (onlyApprovedContractOrEOAStatus) {
            require(tx.origin == msg.sender || approvedContracts[msg.sender], "HoneycombMaster::onlyApprovedContractOrEOA");
        }
        _;
    }

    constructor(
        MintableToken _earningToken,
        uint256 _startTime,
        address _dev,
        address _performanceFeeAddress,
        uint256 _earningsPerSecond
    ) {
        require(_startTime > block.timestamp, "must start in future");
        earningToken = _earningToken;
        startTime = _startTime;
        dev = _dev;
        earningsPerSecond = _earningsPerSecond;
        emit DevSet(address(0), _dev);
        emit PerformanceFeeAddressSet(address(0), _performanceFeeAddress);
    }

    function poolLength() public view returns (uint256) {
        return poolInfo.length;
    }

    function pendingEarnings(uint256 pid, address userAddr) public view returns (uint256) {
        PoolInfo storage pool = poolInfo[pid];
        UserInfo storage user = userInfo[pid][userAddr];
        uint256 accEarningPerShare = pool.accEarningPerShare;
        uint256 poolShares = pool.totalShares;
        if (block.timestamp > pool.lastRewardTime && poolShares != 0) {
            uint256 earningsReward = (reward(pool.lastRewardTime, block.timestamp) * pool.allocPoint) / totalAllocPoint;
            accEarningPerShare = accEarningPerShare + (
                (earningsReward * ACC_EARNING_PRECISION) / poolShares
            );
        }
        return ((user.amount * accEarningPerShare) / ACC_EARNING_PRECISION) - user.rewardDebt;
    }

    function pendingTokens(uint256 pid, address user) external view
        returns (address[] memory, uint256[] memory) {
        uint256 earningAmount = pendingEarnings(pid, user);
        (address[] memory strategyTokens, uint256[] memory strategyRewards) =
            poolInfo[pid].strategy.pendingTokens(pid, user, earningAmount);

        uint256 rewardsLength = 1;
        for (uint256 j = 0; j < strategyTokens.length; j++) {
            if (strategyTokens[j] != address(0)) {
                rewardsLength += 1;
            }
        }
        address[] memory _rewardTokens = new address[](rewardsLength);
        uint256[] memory _pendingAmounts = new uint256[](rewardsLength);
        _rewardTokens[0] = address(earningToken);
        _pendingAmounts[0] = pendingEarnings(pid, user);
        for (uint256 m = 0; m < strategyTokens.length; m++) {
            if (strategyTokens[m] != address(0)) {
                _rewardTokens[m + 1] = strategyTokens[m];
                _pendingAmounts[m + 1] = strategyRewards[m];
            }
        }
        return(_rewardTokens, _pendingAmounts);
    }

    function reward(uint256 _lastRewardTime, uint256 _currentTime) public view returns (uint256) {
        return ((_currentTime - _lastRewardTime) * earningsPerSecond);
    }

    function earningPerYear() public view returns(uint256) {
        //31536000 = seconds per year = 365 * 24 * 60 * 60
        return (earningsPerSecond * 31536000);
    }

    function earningPerYearToHoneycomb(uint256 pid) public view returns(uint256) {
        return ((earningPerYear() * poolInfo[pid].allocPoint) / totalAllocPoint);
    }

    function totalShares(uint256 pid) public view returns(uint256) {
        return poolInfo[pid].totalShares;
    }

    function totalLP(uint256 pid) public view returns(uint256) {
        return (poolInfo[pid].lpPerShare * totalShares(pid) / ACC_EARNING_PRECISION);
    }

    function userShares(uint256 pid, address user) public view returns(uint256) {
        return userInfo[pid][user].amount;
    }

    function updatePool(uint256 pid) public {
        PoolInfo storage pool = poolInfo[pid];
        if (block.timestamp > pool.lastRewardTime) {
            uint256 poolShares = pool.totalShares;
            if (poolShares == 0 || pool.allocPoint == 0) {
                pool.lastRewardTime = block.timestamp;
                return;
            }
            uint256 earningReward = (reward(pool.lastRewardTime, block.timestamp) * pool.allocPoint) / totalAllocPoint;
            pool.lastRewardTime = block.timestamp;
            if (earningReward > 0) {
                uint256 toDev = (earningReward * devMintBips) / MAX_BIPS;
                pool.accEarningPerShare = pool.accEarningPerShare + (
                    (earningReward * ACC_EARNING_PRECISION) / poolShares
                );
                earningToken.mint(dev, toDev);
                earningToken.mint(address(this), earningReward);
            }
        }
    }

    function massUpdatePools() public {
        uint256 length = poolInfo.length;
        for (uint256 pid = 0; pid < length; ++pid) {
            updatePool(pid);
        }
    }

    function deposit(uint256 pid, uint256 amount, address to, address _referrer) external onlyApprovedContractOrEOA {
        uint256 totalAmount = amount;
        updatePool(pid);
        PoolInfo storage pool = poolInfo[pid];
        if (amount > 0) {
            UserInfo storage user = userInfo[pid][to];
            
            if (address(earningReferral) != address(0) && _referrer != address(0) && _referrer != msg.sender) {
                earningReferral.recordReferral(msg.sender, _referrer);
            }
            
            if (pool.depositFeeBP > 0) {
                uint256 depositFee = amount * pool.depositFeeBP / 10000;
                pool.want.safeTransferFrom(address(msg.sender), performanceFeeAddress, depositFee);
                amount = amount - depositFee;
            }

            uint256 newShares = (amount * ACC_EARNING_PRECISION) / pool.lpPerShare;
            pool.want.safeTransferFrom(
                address(msg.sender),
                address(pool.strategy),
                amount
            );
            pool.strategy.deposit(msg.sender, to, amount, newShares);
            pool.totalShares = pool.totalShares + newShares;
            user.amount = user.amount + newShares;
            user.rewardDebt = user.rewardDebt + ((newShares * pool.accEarningPerShare) / ACC_EARNING_PRECISION);
            user.lastDepositTimestamp = block.timestamp;
            deposits[pid][to] += totalAmount;
            emit Deposit(msg.sender, pid, totalAmount, to);
        }
    }

    function withdraw(uint256 pid, uint256 amountShares, address to) external onlyApprovedContractOrEOA {
        updatePool(pid);
        PoolInfo storage pool = poolInfo[pid];
        UserInfo storage user = userInfo[pid][msg.sender];
        require(user.amount >= amountShares, "withdraw: not good");

        if (amountShares > 0) {
            //find amount of LP tokens from shares
            uint256 lpFromShares = (amountShares * pool.lpPerShare) / ACC_EARNING_PRECISION;

            if (pool.isWithdrawFee) {
                uint16 withdrawFeeBP = getWithdrawFee(pid, msg.sender);
                if (withdrawFeeBP > 0) {
                    uint256 withdrawFee = lpFromShares * withdrawFeeBP / 10000;
                    uint256 withdrawFeeShare = amountShares * withdrawFeeBP / 10000;
                    pool.strategy.withdraw(msg.sender, performanceFeeAddress, withdrawFee, withdrawFeeShare);
                    lpFromShares = lpFromShares - withdrawFee;
                    amountShares = amountShares - withdrawFeeShare;
                }
            }

            if (pool.totalShares > amountShares) {
                uint256 lpToSend = lpFromShares;
                withdrawals[pid][to] += lpToSend;
                pool.strategy.withdraw(msg.sender, to, lpToSend, amountShares);
            } else {
                withdrawals[pid][to] += lpFromShares;
                pool.strategy.withdraw(msg.sender, to, lpFromShares, amountShares);
            }

            user.amount = user.amount - amountShares;
            uint256 rewardDebtOfShares = ((amountShares * pool.accEarningPerShare) / ACC_EARNING_PRECISION);
            uint256 userRewardDebt = user.rewardDebt;
            user.rewardDebt = (userRewardDebt >= rewardDebtOfShares) ? (userRewardDebt - rewardDebtOfShares) : 0;
            pool.totalShares = pool.totalShares - amountShares;
            emit Withdraw(msg.sender, pid, amountShares, to);
        }
    }

    function harvest(uint256 pid, address to) external onlyApprovedContractOrEOA {
        updatePool(pid);
        PoolInfo storage pool = poolInfo[pid];
        UserInfo storage user = userInfo[pid][msg.sender];

        uint256 accumulatedEarnings = (user.amount * pool.accEarningPerShare) / ACC_EARNING_PRECISION;
        uint256 pendings = accumulatedEarnings - user.rewardDebt;
        user.rewardDebt = accumulatedEarnings;

        if (pendings > 0) {
            safeEarningsTransfer(to, pendings);
            payReferralCommission(msg.sender, pendings);
        }
        pool.strategy.withdraw(msg.sender, to, 0, 0);
        emit Harvest(msg.sender, pid, pendings);
    }

    function withdrawAndHarvest(uint256 pid, uint256 amountShares, address to) external onlyApprovedContractOrEOA {
        updatePool(pid);
        PoolInfo storage pool = poolInfo[pid];
        UserInfo storage user = userInfo[pid][msg.sender];
        require(user.amount >= amountShares, "withdraw: not good");
        uint256 accumulatedEarnings = (user.amount * pool.accEarningPerShare) / ACC_EARNING_PRECISION;
        uint256 pendings = accumulatedEarnings - user.rewardDebt;
        uint256 lpToSend = (amountShares * pool.lpPerShare) / ACC_EARNING_PRECISION;

        if (pool.isWithdrawFee) {
            uint16 withdrawFeeBP = getWithdrawFee(pid, msg.sender);
            if (withdrawFeeBP > 0) {
                uint256 withdrawFee = lpToSend * withdrawFeeBP / 10000;
                uint256 withdrawFeeShare = amountShares * withdrawFeeBP / 10000;
                pool.strategy.withdraw(msg.sender, performanceFeeAddress, withdrawFee, withdrawFeeShare);
                lpToSend = lpToSend - withdrawFee;
                amountShares = amountShares - withdrawFeeShare;
            }
        }

        if (pool.totalShares > amountShares) {
            withdrawals[pid][to] += lpToSend;
            pool.strategy.withdraw(msg.sender, to, lpToSend, amountShares);
        } else {
            withdrawals[pid][to] += lpToSend;
            pool.strategy.withdraw(msg.sender, to, lpToSend, amountShares);
        }

        user.amount = user.amount - amountShares;
        uint256 rewardDebtOfShares = ((amountShares * pool.accEarningPerShare) / ACC_EARNING_PRECISION);
        user.rewardDebt = accumulatedEarnings - rewardDebtOfShares;
        pool.totalShares = pool.totalShares - amountShares;

        if (pendings > 0) {
            safeEarningsTransfer(to, pendings);
            payReferralCommission(msg.sender, pendings);
        }

        emit Withdraw(msg.sender, pid, amountShares, to);
        emit Harvest(msg.sender, pid, pendings);
    }

    function emergencyWithdraw(uint256 pid, address to) external onlyApprovedContractOrEOA {
        PoolInfo storage pool = poolInfo[pid];
        UserInfo storage user = userInfo[pid][msg.sender];
        uint256 amountShares = user.amount;
        uint256 lpFromShares = (amountShares * pool.lpPerShare) / ACC_EARNING_PRECISION;

        if (pool.isWithdrawFee) {
            uint16 withdrawFeeBP = getWithdrawFee(pid, msg.sender);
            if (withdrawFeeBP > 0) {
                uint256 withdrawFee = lpFromShares * withdrawFeeBP / 10000;
                uint256 withdrawFeeShare = amountShares * withdrawFeeBP / 10000;
                pool.strategy.withdraw(msg.sender, performanceFeeAddress, withdrawFee, withdrawFeeShare);
                lpFromShares = lpFromShares - withdrawFee;
                amountShares = amountShares - withdrawFeeShare;
            }
        }

        if (pool.totalShares > amountShares) {
            uint256 lpToSend = lpFromShares;
            withdrawals[pid][to] += lpToSend;
            pool.strategy.withdraw(msg.sender, to, lpToSend, amountShares);
        } else {
            withdrawals[pid][to] += lpFromShares;
            pool.strategy.withdraw(msg.sender, to, lpFromShares, amountShares);
        }
        user.amount = 0;
        user.rewardDebt = 0;
        pool.totalShares = pool.totalShares - amountShares;
        emit EmergencyWithdraw(msg.sender, pid, amountShares, to);
    }

    function add(uint256 _allocPoint, uint16 _depositFeeBP, IERC20 _want, bool _withUpdate,
        bool _isWithdrawFee, IHoneycombStrategy _strategy)
        external onlyOwner {
        if (_withUpdate) {
            massUpdatePools();
        }
        uint256 lastRewardTime =
            block.timestamp > startTime ? block.timestamp : startTime;
        totalAllocPoint = totalAllocPoint + _allocPoint;
        poolInfo.push(
            PoolInfo({
                want: _want,
                strategy: _strategy,
                allocPoint: _allocPoint,
                lastRewardTime: lastRewardTime,
                accEarningPerShare: 0,
                depositFeeBP: _depositFeeBP,
                isWithdrawFee: _isWithdrawFee,
                totalShares: 0,
                lpPerShare: ACC_EARNING_PRECISION
            })
        );
    }

    function set(
        uint256 _pid,
        uint256 _allocPoint,
        uint16 _depositFeeBP,
        bool _withUpdate,
        bool _isWithdrawFee
    ) external onlyOwner {
        if (_withUpdate) {
            massUpdatePools();
        }
        totalAllocPoint = (totalAllocPoint - poolInfo[_pid].allocPoint) + _allocPoint;
        poolInfo[_pid].allocPoint = _allocPoint;
        poolInfo[_pid].depositFeeBP = _depositFeeBP;
        poolInfo[_pid].isWithdrawFee = _isWithdrawFee;
    }

    function migrateStrategy(uint256 pid, IHoneycombStrategy newStrategy) external onlyOwner {
        PoolInfo storage pool = poolInfo[pid];
        //migrate funds from old strategy to new one
        pool.strategy.migrate(address(newStrategy));
        //update strategy in storage
        pool.strategy = newStrategy;
        newStrategy.onMigration();
    }

    function setStrategy(uint256 pid, IHoneycombStrategy newStrategy, bool transferOwnership, address newOwner)
        external onlyOwner {
        PoolInfo storage pool = poolInfo[pid];
        if (transferOwnership) {
            pool.strategy.transferOwnership(newOwner);
        }
        pool.strategy = newStrategy;
    }

    function manualMint(address dest, uint256 amount) external onlyOwner {
        earningToken.mint(dest, amount);
    }

    function transferMinter(address newMinter) external onlyOwner {
        require(newMinter != address(0));
        earningToken.transferOwnership(newMinter);
    }

    function setDev(address _dev) external onlyOwner {
        require(_dev != address(0));
        emit DevSet(dev, _dev);
        dev = _dev;
    }

    function setPerfomanceFeeAddress(address _performanceFeeAddress) external onlyOwner {
        require(_performanceFeeAddress != address(0));
        emit PerformanceFeeAddressSet(performanceFeeAddress, _performanceFeeAddress);
        performanceFeeAddress = _performanceFeeAddress;
    }

    function setDevMintBips(uint256 _devMintBips) external onlyOwner {
        require(_devMintBips <= MAX_BIPS, "combined dev & nest splits too high");
        devMintBips = _devMintBips;
    }

    function setEarningsEmission(uint256 newEarningsPerSecond, bool withUpdate) external onlyOwner {
        if (withUpdate) {
            massUpdatePools();
        }
        earningsPerSecond = newEarningsPerSecond;
    }

    function modifyApprovedContracts(address[] calldata contracts, bool[] calldata statuses) external onlyOwner {
        require(contracts.length == statuses.length, "input length mismatch");
        for (uint256 i = 0; i < contracts.length; i++) {
            approvedContracts[contracts[i]] = statuses[i];
        }
    }

    function setOnlyApprovedContractOrEOAStatus(bool newStatus) external onlyOwner {
        onlyApprovedContractOrEOAStatus = newStatus;
    }

    function inCaseTokensGetStuck(uint256 pid, IERC20 token, address to, uint256 amount) external onlyOwner {
        IHoneycombStrategy strat = poolInfo[pid].strategy;
        strat.inCaseTokensGetStuck(token, to, amount);
    }

    function setAllowances(uint256 pid) external onlyOwner {
        IHoneycombStrategy strat = poolInfo[pid].strategy;
        strat.setAllowances();
    }

    function revokeAllowance(uint256 pid, address token, address spender) external onlyOwner {
        IHoneycombStrategy strat = poolInfo[pid].strategy;
        strat.revokeAllowance(token, spender);
    }

    function setPerformanceFeeBips(uint256 pid, uint256 newPerformanceFeeBips) external onlyOwner {
        IHoneycombStrategy strat = poolInfo[pid].strategy;
        strat.setPerformanceFeeBips(newPerformanceFeeBips);
    }

    function accountAddedLP(uint256 pid, uint256 amount) external {
        PoolInfo storage pool = poolInfo[pid];
        require(msg.sender == address(pool.strategy), "only callable by strategy contract");
        pool.lpPerShare = pool.lpPerShare + ((amount * ACC_EARNING_PRECISION) / pool.totalShares);
    }

    function safeEarningsTransfer(address _to, uint256 _amount) internal {
        uint256 earningsBal = earningToken.balanceOf(address(this));
        bool transferSuccess = false;
        if (_amount > earningsBal) {
            earningToken.mint(address(this), _amount - earningsBal);
        }
        transferSuccess = earningToken.transfer(_to, _amount);
        require(transferSuccess, "safeEarningsTransfer: transfer failed");
    }
    
    function getWithdrawFee(uint256 _pid, address _user) public view returns (uint16) {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][_user];
        if (!pool.isWithdrawFee)
            return 0;
        uint256 elapsed = block.timestamp - user.lastDepositTimestamp;
        uint i = 0;
        for (; i < withdrawalFeeIntervals.length; i++) {
            if (elapsed < withdrawalFeeIntervals[i])
                break;
        }
        return withdrawalFeeBP[i];
    }
    
    function setWithdrawFee(uint256[] memory _withdrawalFeeIntervals, uint16[] memory _withdrawalFeeBP) public onlyOwner {
        require (_withdrawalFeeIntervals.length + 1 == _withdrawalFeeBP.length, 'setWithdrawFee: _withdrawalFeeBP length is one more than _withdrawalFeeIntervals length');
        require (_withdrawalFeeBP.length > 0, 'setWithdrawFee: _withdrawalFeeBP length is one more than 0');
        for (uint i = 0; i < _withdrawalFeeIntervals.length - 1; i++) {
            require (_withdrawalFeeIntervals[i] < _withdrawalFeeIntervals[i + 1], 'setWithdrawFee: The interval must be ascending');
        }
        for (uint i = 0; i < _withdrawalFeeBP.length; i++) {
            require (_withdrawalFeeBP[i] <= MAX_WITHDRAWAL_FEE_BP, 'setWithdrawFee: invalid withdrawal fee basis points');
        }
        withdrawalFeeIntervals = _withdrawalFeeIntervals;
        withdrawalFeeBP = _withdrawalFeeBP;
    }
    
    function setEarningsReferral(IEarningsReferral _earningReferral) public onlyOwner {
        earningReferral = _earningReferral;
    }

    function setReferralCommissionRate(uint16 _referralCommissionRate) public onlyOwner {
        require(_referralCommissionRate <= MAXIMUM_REFERRAL_COMMISSION_RATE, "setReferralCommissionRate: invalid referral commission rate basis points");
        referralCommissionRate = _referralCommissionRate;
    }

    function payReferralCommission(address _user, uint256 _pending) internal {
        if (address(earningReferral) != address(0) && referralCommissionRate > 0) {
            address referrer = earningReferral.getReferrer(_user);
            uint256 commissionAmount = _pending * referralCommissionRate / 10000;

            if (referrer != address(0) && commissionAmount > 0) {
                earningToken.mint(referrer, commissionAmount);
                earningReferral.recordReferralCommission(referrer, commissionAmount);
                emit ReferralCommissionPaid(_user, referrer, commissionAmount);
            }
        }
    }
}
