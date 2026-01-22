// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity >=0.8.25 <0.9.0;

/**
 * @title MockForwarder
 * @notice A simple mock forwarder for testing ERC-2771 meta-transaction support
 * @dev This contract simulates the behavior of an ERC-2771 trusted forwarder by
 *      appending the original sender's address to the calldata when forwarding calls.
 */
contract MockForwarder {
    /**
     * @notice Forwards a call to a target contract with the sender's address appended
     * @param target The contract to call
     * @param data The original calldata
     * @param originalSender The address to append (the original transaction initiator)
     * @return success Whether the call succeeded
     * @return returnData The return data from the call
     */
    function forward(
        address target,
        bytes calldata data,
        address originalSender
    ) external returns (bool success, bytes memory returnData) {
        // Append the original sender address to the calldata (ERC-2771 format)
        bytes memory forwardedData = abi.encodePacked(data, originalSender);

        (success, returnData) = target.call(forwardedData);
    }

    /**
     * @notice Forwards a call and reverts if the call fails
     * @param target The contract to call
     * @param data The original calldata
     * @param originalSender The address to append (the original transaction initiator)
     * @return returnData The return data from the call
     */
    function forwardOrRevert(
        address target,
        bytes calldata data,
        address originalSender
    ) external returns (bytes memory returnData) {
        bytes memory forwardedData = abi.encodePacked(data, originalSender);

        bool success;
        (success, returnData) = target.call(forwardedData);

        if (!success) {
            // Bubble up the revert reason
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
