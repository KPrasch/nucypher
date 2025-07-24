// SPDX-License-Identifier: AGPL-3.0-or-later

pragma solidity ^0.8.0;

/**
 * @notice Contract for testing bridge destination functionality
 */
contract BridgeDestinationContract {
    enum IntentStatus {
        INACTIVE,
        AWAITING_EXECUTION,
        EXECUTED,
        CANCELLED
    }

    // Simple mappings for testing
    mapping(uint256 => uint256) private intentToOrder;
    mapping(uint256 => uint256) private orderToIntent;
    mapping(uint256 => IntentStatus) private intentStatuses;
    mapping(uint256 => address) private fulfillerAddresses;
    mapping(uint256 => uint256[]) private intents;

    constructor() {
        // Set up some test data
        // Intent ID 1 -> Order ID 1
        intentToOrder[1] = 1;
        orderToIntent[1] = 1;
        
        // Intent 1 is awaiting execution
        intentStatuses[1] = IntentStatus.AWAITING_EXECUTION;
        
        // Intent 1 has a fulfiller
        fulfillerAddresses[1] = address(0x1234567890123456789012345678901234567890);
        
        // Intent 1 has some data (not [0,0,0])
        intents[1] = [100, 200, 300];
    }

    function getOrderID(uint256 intentId) external view returns (uint256) {
        return intentToOrder[intentId];
    }

    function getIntentStatus(uint256 intentId) external view returns (IntentStatus) {
        return intentStatuses[intentId];
    }

    function getIntent(uint256 intentId) external view returns (uint256[] memory) {
        return intents[intentId];
    }

    function getIntentID(uint256 orderId) external view returns (uint256) {
        return orderToIntent[orderId];
    }

    function getFulfillerAddress(uint256 intentId) external view returns (address) {
        return fulfillerAddresses[intentId];
    }

    // Function to execute an intent (for the signing condition)
    function executeIntent(uint256 intentId, address requester) external {
        require(intentStatuses[intentId] == IntentStatus.AWAITING_EXECUTION, "Intent not ready");
        intentStatuses[intentId] = IntentStatus.EXECUTED;
    }
} 
