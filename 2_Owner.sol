// SPDX-License-Identifier: GPL-3.0

pragma solidity 0.8.0;

/**
 * @title Owner
 * @dev Set & change owner
 */
contract Counter {
    address owner;    // current owner of the contract

    function TipJar() public {  // contract's constructor function
        owner = msg.sender;
    }

    function withdraw() public {
        require(owner == msg.sender);
        msg.sender.transfer(address(this).balance);
    }

}