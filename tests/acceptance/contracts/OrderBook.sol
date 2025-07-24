// SPDX-License-Identifier: AGPL-3.0-or-later

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/math/Math.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract OrderBook {
    using SafeERC20 for IERC20;

    address public immutable thresholdSigner;
    uint256 public immutable chainIdFrom;
    uint256 public immutable chainIdTo;
    uint256 public immutable maxTimeout;

    constructor(address _thresholdSigner, uint256 _maxTimeout) {
        thresholdSigner = _thresholdSigner;
        chainIdFrom = 1;
        chainIdTo = 1;
        maxTimeout = _maxTimeout;
    }

    modifier onlySigner() {
        require(msg.sender == thresholdSigner, "Nope");
        _;
    }

    enum OrderState {
        INACTIVE,
        AWAITING_FULFILLMENT,
        REFUNDED,
        CANCELED,
        EXECUTED
    }

    struct Order {
        address requester;
        IERC20 tokenFrom;
        uint256 amountFrom;
        address tokenTo;
        uint256 amountTo;
        address receiverAddress;
        uint256 endTimestamp;
        OrderState state;
    }

    mapping(uint256 id => Order order) public orders;
    uint256 public ordersLength;

    function request(
        IERC20 tokenFrom,
        uint256 amountFrom,
        address tokenTo,
        uint256 amountTo,
        address receiverAddress,
        uint256 timeout
    ) external returns (uint256 orderId) {
        orderId = ordersLength;
        ordersLength++;
        Order storage order = orders[orderId];
        order.requester = msg.sender;
        order.tokenFrom = tokenFrom;
        order.amountFrom = amountFrom;
        order.tokenTo = tokenTo;
        order.amountTo = amountTo;
        order.receiverAddress = receiverAddress;
        order.endTimestamp = block.timestamp + Math.min(timeout, maxTimeout);
        order.state = OrderState.AWAITING_FULFILLMENT;
        tokenFrom.transferFrom(msg.sender, address(this), amountFrom);
    }

    function request(
        address tokenTo,
        uint256 amountTo,
        address receiverAddress,
        uint256 timeout
    ) external payable returns (uint256 orderId) {
        orderId = ordersLength;
        ordersLength++;
        Order storage order = orders[orderId];
        order.requester = msg.sender;
        order.tokenFrom = IERC20(address(0));
        order.amountFrom = msg.value;
        order.tokenTo = tokenTo;
        order.amountTo = amountTo;
        order.receiverAddress = receiverAddress;
        order.endTimestamp = block.timestamp + Math.min(timeout, maxTimeout);
        order.state = OrderState.AWAITING_FULFILLMENT;
    }

    function getRequesterAddress(uint256 orderId) external view returns (address) {
        return orders[orderId].receiverAddress;
    }

    function getOrder(uint256 orderId) external view returns (address token, uint256 amount) {
        Order storage order = orders[orderId];
        if (block.timestamp > order.endTimestamp) {
            return (address(0), 0);
        }
        token = order.tokenTo;
        amount = order.amountTo;
    }

    function getOrderStatus(uint256 orderId) external view returns (OrderState) {
        return orders[orderId].state;
    }

    function claimOrder(uint256 orderId, address receiverAddress) external onlySigner {
        Order storage order = orders[orderId];
        require(order.state == OrderState.AWAITING_FULFILLMENT, "Nope");
        order.state == OrderState.EXECUTED;
        if (address(order.tokenFrom) == address(0)) {
            (bool success, ) = receiverAddress.call{value: order.amountFrom}(""); // re-entry is fine here
            require(success, "Sending ETH failed");
        } else {
            order.tokenFrom.transfer(receiverAddress, order.amountFrom);
        }
    }

    enum IntentState {
        INACTIVE,
        AWAITING_EXECUTION,
        EXECUTED,
        CANCELLED
    }

    struct Intent {
        uint256 orderId;
        address fulfiller;
        IERC20 tokenTo;
        uint256 amountTo;
        address receiverAddress;
        IntentState state;
    }

    mapping(uint256 intentId => Intent intent) public intents;
    mapping(uint256 orderId => uint256 intentId) public fulfilledOrders;
    uint256 public intentsLength;

    function submitIntent(
        uint256 orderId,
        IERC20 token,
        uint256 amount,
        address receiverAddress
    ) external returns (uint256 intentId) {
        intentId = intentsLength;
        intentsLength++;
        Intent storage intent = intents[intentId];
        intent.orderId = orderId;
        intent.fulfiller = msg.sender;
        intent.tokenTo = token;
        intent.amountTo = amount;
        intent.receiverAddress = receiverAddress;
        intent.state = IntentState.AWAITING_EXECUTION;
        token.transferFrom(msg.sender, address(this), amount);
    }

    function submitIntent(
        uint256 orderId,
        address receiverAddress
    ) external payable returns (uint256 intentId) {
        intentId = intentsLength;
        intentsLength++;
        Intent storage intent = intents[intentId];
        intent.orderId = orderId;
        intent.fulfiller = msg.sender;
        intent.tokenTo = IERC20(address(0));
        intent.amountTo = msg.value;
        intent.receiverAddress = receiverAddress;
        intent.state = IntentState.AWAITING_EXECUTION;
    }

    // function cancelIntent()

    function getOrderID(uint256 intentId) external view returns (uint256) {
        return intents[intentId].orderId;
    }

    function getIntentStatus(uint256 intentId) external view returns (IntentState) {
        return intents[intentId].state;
    }

    function getIntent(uint256 intentId) external view returns (IERC20 token, uint256 amount) {
        Intent storage intent = intents[intentId];
        token = intent.tokenTo;
        amount = intent.amountTo;
    }

    function executeIntent(uint256 intentId, address receiverAddress) external onlySigner {
        Intent storage intent = intents[intentId];
        require(intent.state == IntentState.AWAITING_EXECUTION, "Nope");
        intent.state == IntentState.EXECUTED;
        fulfilledOrders[intent.orderId] = intentId;
        if (address(intent.tokenTo) == address(0)) {
            (bool success, ) = receiverAddress.call{value: intent.amountTo}(""); // re-entry is fine here
            require(success, "Sending ETH failed");
        } else {
            intent.tokenTo.transfer(receiverAddress, intent.amountTo);
        }
    }

    function getIntentID(uint256 orderId) external view returns (uint256) {
        return fulfilledOrders[orderId];
    }

    function getFulfillerAddress(uint256 intentID) external view returns (address) {
        return intents[intentID].receiverAddress;
    }
}
