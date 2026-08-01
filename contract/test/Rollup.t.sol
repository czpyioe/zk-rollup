// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {Rollup, IVerifier} from "../src/Rollup.sol";
import {Verifier} from "../src/Verifier.sol";

contract RollupTest is Test {
    Rollup rollup;
    Verifier verifier;

    address sequencer = makeAddr("sequencer");
    address stranger = makeAddr("stranger");

    // proof and roots generated with prover/src/bin/gen_batch_proof.rs
    // keys used should match the one used for the Verifier.sol generation
    bytes32 constant GENESIS_ROOT = bytes32(0x0fae6368f7f3a04655da2c6de2d9962be2dea294bcae334da0f51316c218573a);
    bytes32 constant NEW_ROOT = bytes32(0x1df66c6e9c927e6d759c6f0225cb65cd44c92af530dda5d99410fd85c2bbf919);
    bytes32 constant BATCH_HASH = bytes32(0x27f9e58032bf504b3b41ce11dd50ed329e928ea486a3e85357730ca525c9290c);
    bytes constant PROOF =
        hex"3035224906c04ddb507a303a6b76f1a37fd3c057be27a62bae5e3475708ead0d261964c12bfa84ca1126718a89aea8658b0268ceb6b66fc66528711bf765a23d16c2f73e666b6f449b2d8ae7b087e5a09cef6c2240b0412f20e18764d7f7d65a27ebef840dbb5f7f216e93a053ff8751f7215d06557258994650c163ad906e3d063aa38bf4cdc4ddb4790dab31e913677a1111834eb7265d088410eb62542c9f1a0ade1ebe89e7916bbb9f744d888980ab2c5250c5456b288651b7b04c5dc98c064b6d24ea2beafa8241ce46f91098d4f99fcd22d64c465147bf8b3cc8c5ff66139ba24f8199d3bf22a7bc3012febdb9ff42342367d739cb8573ad87b34dcc03";
            
    function setUp() public {
        verifier = new Verifier();
        rollup = new Rollup(IVerifier(address(verifier)), sequencer, GENESIS_ROOT);
    }

    function test_process_batch_updates_root() public {
        vm.prank(sequencer);
        rollup.process_batch(PROOF, GENESIS_ROOT, NEW_ROOT, BATCH_HASH);

        assertEq(rollup.current_root(), NEW_ROOT);
        assertEq(rollup.index(), 1);
    }

    function test_process_batch_reverts_for_non_sequencer() public {
        vm.prank(stranger);
        vm.expectRevert();
        rollup.process_batch(PROOF, GENESIS_ROOT, NEW_ROOT, BATCH_HASH);
    }

    function test_process_batch_reverts_on_wrong_old_root() public {
        vm.prank(sequencer);
        vm.expectRevert("old root isn't equal to the current root");
        rollup.process_batch(PROOF, bytes32(uint256(1)), NEW_ROOT, BATCH_HASH);
    }

    function test_process_batch_reverts_on_wrong_new_root() public {
        vm.prank(sequencer);
        vm.expectRevert("invalid proof");
        rollup.process_batch(PROOF, GENESIS_ROOT, bytes32(uint256(1)), BATCH_HASH);
    }

    function test_process_batch_reverts_on_wrong_batch_hash() public {
        vm.prank(sequencer);
        vm.expectRevert("invalid proof");
        rollup.process_batch(PROOF, GENESIS_ROOT, NEW_ROOT, bytes32(uint256(1)));
    }

    function test_process_batch_cannot_replay_same_batch() public {
        vm.prank(sequencer);
        rollup.process_batch(PROOF, GENESIS_ROOT, NEW_ROOT, BATCH_HASH);

        vm.prank(sequencer);
        vm.expectRevert("old root isn't equal to the current root");
        rollup.process_batch(PROOF, GENESIS_ROOT, NEW_ROOT, BATCH_HASH);
    }
}
