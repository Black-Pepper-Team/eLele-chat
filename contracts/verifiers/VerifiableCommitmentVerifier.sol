// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.9.0;

contract VerifiableCommitmentVerifier {
    /// @dev Base field size
    uint256 public constant BASE_FIELD_SIZE =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    /// @dev Verification Key data
    uint256 public constant ALPHA_X =
        20491192805390485299153009773594534940189261866228447918068658471970481763042;
    uint256 public constant ALPHA_Y =
        9383485363053290200918347156157836566562967994039712273449902621266178545958;
    uint256 public constant BETA_X1 =
        4252822878758300859123897981450591353533073413197771768651442665752259397132;
    uint256 public constant BETA_X2 =
        6375614351688725206403948262868962793625744043794305715222011528459656738731;
    uint256 public constant BETA_Y1 =
        21847035105528745403288232691147584728191162732299865338377159692350059136679;
    uint256 public constant BETA_Y2 =
        10505242626370262277552901082094356697409835680220590971873171140371331206856;
    uint256 public constant GAMMA_X1 =
        11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 public constant GAMMA_X2 =
        10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 public constant GAMMA_Y1 =
        4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 public constant GAMMA_Y2 =
        8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 public constant DELTA_X1 =
        16552292026754325382160795028120577645232930235593636828284685894470552345176;
    uint256 public constant DELTA_X2 =
        5609758638718809935996139453891211764590899362609226029657455216029224031479;
    uint256 public constant DELTA_Y1 =
        4417650727447023195835773371168473084295541727686090146194803631072763224979;
    uint256 public constant DELTA_Y2 =
        9252602708562345859188234973301128759367831913208831621553343907027923931208;

    uint256 public constant IC0_X =
        16808794605717666249948725876854277698460648021966666081602141149800894988474;
    uint256 public constant IC0_Y =
        18848042556172368953661176423084447280472424754251348616917863523522667039275;
    uint256 public constant IC1_X =
        6938486927121562377533100332522257121442123135214963119922463411004812492509;
    uint256 public constant IC1_Y =
        7485157327556907547476141741629094665094766563626818599658409704260019055839;
    uint256 public constant IC2_X =
        10455107769255179940529155062647887607849798397567798168836723522633412342656;
    uint256 public constant IC2_Y =
        8354698781456771025384871144577433146993184168728803179072497138000820463026;
    uint256 public constant IC3_X =
        15548765287726183550106159815479547121542349882395927224220623307627557513059;
    uint256 public constant IC3_Y =
        11812977136864511441547531147033771183855158686512439362093836359271533516400;
    uint256 public constant IC4_X =
        14917182979826487839479230200319774326398419864655111550608732469624654839694;
    uint256 public constant IC4_Y =
        20848425664845331851697556563408642492848380368800359982679354015237415435369;
    uint256 public constant IC5_X =
        17131553333672232794481062971787883457482111112061461612909159677313352700121;
    uint256 public constant IC5_Y =
        3022014374785440502695617502340681268321906573555947466506779808377630814472;

    /// @dev Memory data
    uint16 public constant P_VK = 0;
    uint16 public constant P_PAIRING = 128;
    uint16 public constant P_LAST_MEM = 896;

    function verifyProof(
        uint256[2] calldata pA_,
        uint256[2][2] calldata pB_,
        uint256[2] calldata pC_,
        uint256[5] calldata pubSignals_
    ) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, BASE_FIELD_SIZE)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            /// @dev G1 function to multiply a G1 value(x,y) to value in an address
            function g1MulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)

                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let pPairing_ := add(pMem, P_PAIRING)
                let pVk_ := add(pMem, P_VK)

                mstore(pVk_, IC0_X)
                mstore(add(pVk_, 32), IC0_Y)

                /// @dev Compute the linear combination vk_x
                g1MulAccC(pVk_, IC1_X, IC1_Y, calldataload(add(pubSignals, 0)))
                g1MulAccC(pVk_, IC2_X, IC2_Y, calldataload(add(pubSignals, 32)))
                g1MulAccC(pVk_, IC3_X, IC3_Y, calldataload(add(pubSignals, 64)))
                g1MulAccC(pVk_, IC4_X, IC4_Y, calldataload(add(pubSignals, 96)))
                g1MulAccC(pVk_, IC5_X, IC5_Y, calldataload(add(pubSignals, 128)))

                /// @dev -A
                mstore(pPairing_, calldataload(pA))
                mstore(
                    add(pPairing_, 32),
                    mod(sub(BASE_FIELD_SIZE, calldataload(add(pA, 32))), BASE_FIELD_SIZE)
                )

                /// @dev B
                mstore(add(pPairing_, 64), calldataload(pB))
                mstore(add(pPairing_, 96), calldataload(add(pB, 32)))
                mstore(add(pPairing_, 128), calldataload(add(pB, 64)))
                mstore(add(pPairing_, 160), calldataload(add(pB, 96)))

                /// @dev alpha1
                mstore(add(pPairing_, 192), ALPHA_X)
                mstore(add(pPairing_, 224), ALPHA_Y)

                /// @dev beta2
                mstore(add(pPairing_, 256), BETA_X1)
                mstore(add(pPairing_, 288), BETA_X2)
                mstore(add(pPairing_, 320), BETA_Y1)
                mstore(add(pPairing_, 352), BETA_Y2)

                /// @dev vk_x
                mstore(add(pPairing_, 384), mload(add(pMem, P_VK)))
                mstore(add(pPairing_, 416), mload(add(pMem, add(P_VK, 32))))

                /// @dev gamma2
                mstore(add(pPairing_, 448), GAMMA_X1)
                mstore(add(pPairing_, 480), GAMMA_X2)
                mstore(add(pPairing_, 512), GAMMA_Y1)
                mstore(add(pPairing_, 544), GAMMA_Y2)

                /// @dev C
                mstore(add(pPairing_, 576), calldataload(pC))
                mstore(add(pPairing_, 608), calldataload(add(pC, 32)))

                /// @dev delta2
                mstore(add(pPairing_, 640), DELTA_X1)
                mstore(add(pPairing_, 672), DELTA_X2)
                mstore(add(pPairing_, 704), DELTA_Y1)
                mstore(add(pPairing_, 736), DELTA_Y2)

                let success_ := staticcall(sub(gas(), 2000), 8, pPairing_, 768, pPairing_, 0x20)

                isOk := and(success_, mload(pPairing_))
            }

            let pMem_ := mload(0x40)
            mstore(0x40, add(pMem_, P_LAST_MEM))

            /// @dev Validate that all evaluations ∈ F
            checkField(calldataload(add(pubSignals_, 0)))
            checkField(calldataload(add(pubSignals_, 32)))
            checkField(calldataload(add(pubSignals_, 64)))
            checkField(calldataload(add(pubSignals_, 96)))
            checkField(calldataload(add(pubSignals_, 128)))
            checkField(calldataload(add(pubSignals_, 160)))

            /// @dev Validate all evaluations
            let isValid := checkPairing(pA_, pB_, pC_, pubSignals_, pMem_)

            mstore(0, isValid)
            return(0, 0x20)
        }
    }
}
