// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity >=0.8.25 <0.9.0;

// Mock ERC-2771 forwarder for testing
contract MockForwarder {
    function forward(
        address target,
        bytes calldata data,
        address originalSender
    ) external returns (bool success, bytes memory returnData) {
        bytes memory forwardedData = abi.encodePacked(data, originalSender);
        (success, returnData) = target.call(forwardedData);
    }

    function forwardOrRevert(
        address target,
        bytes calldata data,
        address originalSender
    ) external returns (bytes memory returnData) {
        bytes memory forwardedData = abi.encodePacked(data, originalSender);

        bool success;
        (success, returnData) = target.call(forwardedData);

        if (!success) {
            if (returnData.length > 0) {
                assembly {
                    let returnDataSize := mload(returnData)
                    revert(add(32, returnData), returnDataSize)
                }
            } else {
                revert("MockForwarder: call failed");
            }
        }
    }
}
