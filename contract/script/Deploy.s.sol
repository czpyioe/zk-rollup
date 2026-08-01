// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {Verifier} from "../src/Verifier.sol";
import {Rollup, IVerifier} from "../src/Rollup.sol";

contract Deploy is Script {
    function run() external {
        address sequencerAddr = vm.envAddress("SEQUENCER_ADDRESS");
        bytes32 genesisRoot = vm.envBytes32("GENESIS_ROOT");

        vm.startBroadcast();

        Verifier verifier = new Verifier();
        Rollup rollup = new Rollup(IVerifier(address(verifier)), sequencerAddr, genesisRoot);

        vm.stopBroadcast();

        console.log("Verifier :", address(verifier));
        console.log("Rollup :", address(rollup));
    }
}
