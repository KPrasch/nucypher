// SPDX-License-Identifier: AGPL-3.0-or-later

pragma solidity ^0.8.0;

/**
 * @notice Contract for testing bridge origin functionality
 */
contract BridgeOriginContract {
    enum OrderStatus {
        INACTIVE,
        AWAITING_FULFILLMENT,
        REFUNDED
    }

    // Simple mappings for testing
    mapping(uint256 => address) private requesterAddresses;
    mapping(uint256 => uint256[]) private orders;
    mapping(uint256 => OrderStatus) private orderStatuses;

    constructor() {
        // Set up some test data
        // Order ID 1 has a requester
        requesterAddresses[1] = address(0xABcdEFABcdEFabcdEfAbCdefabcdeFABcDEFabCD);
        
        // Order 1 has the same data as intent 1 (must match for test to pass)
        orders[1] = [100, 200, 300];
        
        // Order 1 is awaiting fulfillment
        orderStatuses[1] = OrderStatus.AWAITING_FULFILLMENT;
    }

    function getRequesterAddress(uint256 orderId) external view returns (address) {
        return requesterAddresses[orderId];
    }

    function getOrder(uint256 orderId) external view returns (uint256[] memory) {
        return orders[orderId];
    }

    function getOrderStatus(uint256 orderId) external view returns (OrderStatus) {
        return orderStatuses[orderId];
    }

    // Function to claim an order (for the signing condition)
    function claimOrder(uint256 orderId, address fulfiller) external {
        require(orderStatuses[orderId] == OrderStatus.AWAITING_FULFILLMENT, "Order not ready");
        orderStatuses[orderId] = OrderStatus.REFUNDED;
    }

    // Additional functions that might be needed
    function request(uint256 orderId, address requester, uint256[] memory orderData) external {
        requesterAddresses[orderId] = requester;
        orders[orderId] = orderData;
        orderStatuses[orderId] = OrderStatus.AWAITING_FULFILLMENT;
    }
} 
