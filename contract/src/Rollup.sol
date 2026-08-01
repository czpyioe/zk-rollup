// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

interface IVerifier {
    function verifyProof(bytes memory _proof, uint256[3] memory _input) external view returns (bool);
}

contract Rollup {

    IVerifier public immutable verifier;
    uint256 public index = 0;
    bytes32 public current_root;

    address immutable sequencer;

    event BatchProcessed(uint256 indexed idx, bytes32 old_root, bytes32 new_root, bytes32 batch_hash);


    constructor(IVerifier _verifier,address _sequencer, bytes32 _genesis_root) {
        verifier = _verifier;
        sequencer = _sequencer;
        current_root=_genesis_root;
    }

    modifier onlySequencer(){
        require(msg.sender==sequencer);
        _;
    }

    function process_batch(
        bytes calldata _proof,
        bytes32 _old_root,
        bytes32 _new_root,
        bytes32 _batch_hash
    ) external onlySequencer(){
        require(_old_root==current_root,"old root isn't equal to the current root");

        require(
            verifier.verifyProof(
                _proof, 
                [
                    uint256(_old_root),
                    uint256(_new_root),
                    uint256(_batch_hash)
                ]
            ),
            "invalid proof"
        );

        emit BatchProcessed(index, _old_root, _new_root, _batch_hash);
        current_root = _new_root;
        index++;
    }

}
