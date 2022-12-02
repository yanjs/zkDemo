// SPDX-License-Identifier: MIT
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;
library Pairing {
    struct G1Point {
        uint X;
        uint Y;
    }
    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint[2] X;
        uint[2] Y;
    }
    /// @return the generator of G1
    function P1() pure internal returns (G1Point memory) {
        return G1Point(1, 2);
    }
    /// @return the generator of G2
    function P2() pure internal returns (G2Point memory) {
        return G2Point(
            [10857046999023057135944570762232829481370756359578518086990519993285655852781,
             11559732032986387107991004021392285783925812861821192530917403151452391805634],
            [8495653923123431417604973247489272438418190587263600148770280649306958101930,
             4082367875863433681332203403145435568316851327593401208105741076214120093531]
        );
    }
    /// @return the negation of p, i.e. p.addition(p.negate()) should be zero.
    function negate(G1Point memory p) pure internal returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }
    /// @return r the sum of two points of G1
    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
    }


    /// @return r the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(G1Point memory p, uint s) internal view returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success);
    }
    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == p2.length);
        uint elements = p1.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](inputSize);
        for (uint i = 0; i < elements; i++)
        {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[1];
            input[i * 6 + 3] = p2[i].X[0];
            input[i * 6 + 4] = p2[i].Y[1];
            input[i * 6 + 5] = p2[i].Y[0];
        }
        uint[1] memory out;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
        return out[0] != 0;
    }
    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for three pairs.
    function pairingProd3(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](3);
        G2Point[] memory p2 = new G2Point[](3);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for four pairs.
    function pairingProd4(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2,
            G1Point memory d1, G2Point memory d2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p1[3] = d1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        p2[3] = d2;
        return pairing(p1, p2);
    }
}

contract SplitVerifier {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(uint256(0x141de25315ca3d503a2bc502ba8480d616ecfa9af33f46967ba7f93c113d6796), uint256(0x097fd586b9701c6795922ed62f1b009008401ea1de2c43e92241ed7bfd867080));
        vk.beta = Pairing.G2Point([uint256(0x2e7f55daaae9fdb64af6b1bbab79e3e825ff8177dc421ca23ca93ae9c8eb476c), uint256(0x217d2c1816f2b70251f8160978da16bbe05b1843d5530573e2fc3fe18e89a5d4)], [uint256(0x2555fb4897f3703929c0de22e4dcc53c3fd9020e160ba93095ea5d49f87dc259), uint256(0x2d34e7b60a9ca7576c4e9f86bab664b546c2ecfdbb1528c4affdbaeee650d311)]);
        vk.gamma = Pairing.G2Point([uint256(0x1ec882745e6ed3988b627633f4f857b7cf61fde6a16d28ab72ae6f0899885d95), uint256(0x0a981bb51555462576a136401612d3483e9ec6bc08895cab74de5d5d6e3e424c)], [uint256(0x0743824543b1000f88136c8dfd64c8b2c16eaa3422d34251d9c71dab23301dce), uint256(0x2600f6f6e38a163563a32a8f54eecfe3d9fc3215094dae73a46ad68f12605851)]);
        vk.delta = Pairing.G2Point([uint256(0x2f0fb750a7756608bbacce23202ed03dc2b51d95df80741e252e38892b33c923), uint256(0x2b13a078d94debff6381c25d130908ccb03eaf9932d065d2ea235d76a0b9f434)], [uint256(0x08fd6937158a56d506e1ee3cdad97938d47020647a8de332a50f5d9cad5f3707), uint256(0x2d1ed478d7feea4816c68cb5d46945ee87d03cbd8ff5402d4b33ae1eed5f560c)]);
        vk.gamma_abc = new Pairing.G1Point[](89);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x0f527a9606fda8f5607a5a96456f1ad19be31f4e7ef7dc847a3dbffa0f10d95f), uint256(0x17528bba19830219731271e6b9410cfe73c916dfedd22883711e34fc826d9f12));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x176a3ad17eefef176b5f8840e3015729c000a6a3d211a5a08cd8329573a3d7bb), uint256(0x2dedc933e9f7494525c527a328ddbf3654add856dd12e2bf5c63b9ade418b57a));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x1dbd04c5c282db1c1130f4463bbd91f1924bb8e5252ecfdbab7c8251a487ca06), uint256(0x12ced7cea8b9d1d813e3d277b43455efe638b8251635b583340ac3a23b73ed91));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x0475f143a674ba4a98416e94184efc46e358a5b0b97e7bb3e4a107a4bf154a41), uint256(0x2c379f81bb4f0d9d94e3d4a3a700c08803205ddd7f69e22b189a12bb2caa774f));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x201d56b7f551f295e9d248b0814da78c4ba8d947e73cc240c391a54c34d7419e), uint256(0x175a99b1cf6e2de682346a2254ac25263dc468ae7851aa02b1cd4513dba56ed8));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x2bfe73eba860604447b56b929fe9bff88b66cf13c167bd0a7311eca509253f49), uint256(0x04977a455f933e259d7b7c585ce615aec00238aed40189b5fcb0d7390c0ea863));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x09c4d865706b44d935d806a9645f17faba34955ae261dfef1a834afe986caf19), uint256(0x28b4a7e9fa4444d021277164bc4f021b1c89f385d0c3d0809f0d8de5d0f4701c));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x05bdc0763328487bc5cbadd3a746e58a6977740b43f35e137c4689b6fbada153), uint256(0x0be19ecf1d3b5fcb00c2aaa847c141166dce0b735b809d218f25308d272b6da8));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x2b2c2add8a94b55fc5afd8037c6f8f96badbfac2f3053f82af13e2a0338b9f90), uint256(0x216c2ad3dc713979d534cf2a83141bb0cbebc0a1e8fde7c802c92b53779fc793));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x29c04de6688d3a7d2ebd422d94f5b70a4d401e8e5980b10a9f03e0c0d632bab2), uint256(0x27d4ac10dc591e28bdc8a33ab89b31745dcbbb989b469d9e8809abfc6e208922));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x2c9006db7e089413dc59a46a64e8032560553d36781452ec6ded8ce5e08c2657), uint256(0x2d7432ebe21099877f266ce00bb35fafa7ad4960a637ed147f0f4e1c66d3a3b7));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x1a246474c67556442c35c70be7d2819504a149fef532f043172eff853ef44de3), uint256(0x139fa342497bab70dc6ec7ce50a6069201dec1fc82b107b63746630b56c92d80));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x2f7ec6ff23fedf3896642760b178c2cd7e17d8004406e61254b827b43ea82ccb), uint256(0x1c045a90e5173265fd308b4b8eab5d96c4d0f40db973c3493d1f85b1a174b188));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x220aab35f23c39a9c78e9d088f90ee277a6f07f910d0dceb94987dde10e58ffe), uint256(0x2ec500ef185170ae63cdeb99a5f4984b3b18ae5907306cb589b3447f5895a26f));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x14bc2f7d031a934f5a32d7b2d40de664d6bde0411dc18ec932ca948069633f35), uint256(0x133283c126ec02090718479b75343c94b7b568359cee663d38d11bd88297e3c8));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x1768f20978f8e7e1145ea7bd58a54b84a122399f7f08e20a8dcbe75a230dcf3e), uint256(0x160da5333fa6c6453f714910b9f768c710983bf28c315b1a50b191fab1d9364f));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x254021801e9ae4f0f1ac247e718b0d05fe19ab966679704235e476a0064ba89e), uint256(0x064c53c368ec326cae41a620722976c0c87ee40929c28889a3b58380af01c5f0));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x0f5b2c576a58597afd8b44eccaf9bd51bcd778f4ee12339443932aa4628b4056), uint256(0x2440cb1d7e71382222bf858fb737cc83290d01db9dc3620fb4370b2ddff57d53));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x1540bd1d89fc678af50a4cf93fe97d5579bfdb3c20f044d67166840e0b11ab54), uint256(0x2bb7b56a3d1d919a43ef937293b45947cce8b88e58919843bb04f1e047003d83));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x0c19a707c488356939b4b2f612b2f875d7fbf634a1fc8ac2c07afc3fd5d4c68a), uint256(0x2356d4fa117bdf89f9dd7b44b9f01ed1188cd9aeac1159d6bc6bb983bb504943));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x021940088d16f7f59692bafe73bfecba43c5cdd750fc6dfb25ed7ef5b3dd81c1), uint256(0x2490c6d29e58ff3c7f349f09e6898ce3657f0eaeec675cc0d25deb03e1bc21b3));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x0e4b015c3691567cad935a3d386917fe29b955614e9a429d9f76185f1e9a2d96), uint256(0x2ffff6cd504320082106034cedff173633f9cd3398bdcfd72e463d09f45d7884));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x13e4ac4b4c1e4a7eef369510eaa54e17268722492af584c5a0d2958f533c9996), uint256(0x1ee111b1c9f80cbf99b41619ef010219a4fec33e69df17522315dadf5801363a));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x2b193fc7133159585d3d554022177d5f8fafa0dc2cc8e013e6697318b65619d4), uint256(0x22b9ba69d81223a4a341d0140775ea1742f9ca1f72612856d2e87903b9b26c1a));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x1bcf4029ae081ce080f495382b7bd75d2531e4fc2b71ae74443d9e80b59fafae), uint256(0x131de87b9c433d6849bc9f7f7112e47dfcffbc484f56cc7a0ef2c43bbeff3e51));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x0d902c13f850e1e35df7770a4a759e724fe9cebdc57df7865a419ca30a7ff687), uint256(0x1bb052c8072ee4bd940098837c39e1fb865793f3d7c256fbbe879d81bb8a0f88));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x1d28e6b46ddf7d0988a6c0d9bd14adf3bddf97217108e239acf1d748e66c8133), uint256(0x1032c0b79822191b9373c6057563d7f0dc9c9d5bf14bdbe0a3439d5260be046c));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x0a3bcfe78825cc8721a2ea6021f15a0005bd25b59608d9556baf94a71374f97f), uint256(0x024842c8313a805d5d8f817ebe5338e469e3527a172e291b70bbc68ceb88a286));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x2f02a6482eec1e537bf7e832164ac9f17f0439642a9f392963c533e72f461b3b), uint256(0x0a9aef82266b2820f40dcc3a6f521842799dde324d59402b8f576184a45ded79));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x028b03ee9a3888b869a82afd2183e6cff2dc54471b6ad6a6da414b523c4b72dd), uint256(0x1cbc329b062ec8faf4ecc3df5029242802c1bbedc0d7b4fb4172d76800fa7c2e));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x0510f43b9db82b93b31670608515ccc7a5058a946f364247e846e9d3da2f8390), uint256(0x13368c0dff50913c793ff7c1f6498ca7bb57e3dc41afe44f277386429d4e30d8));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x0ed903bf5bc063940bd1930a2397b8edcd50c444fdf39d870a72ec6b19bd1de8), uint256(0x0c8ecb4016e8ca3b6da69e9f06c1f5b235b54ee6edb5823c6d180b4a2db2b96f));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x157ae9a38ef9c291a2bb291a7aec9bd47e5f8ac5a00c0530e67ac68ef0efef66), uint256(0x01f2f95969054e0a285103342764830d8711f6646807ebb60f1dd88a8a29f7f2));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x1e74433e5db48ef5553b22b0fa4b5921aa1634eade868f9813adb30efd1e4fc6), uint256(0x30546d8fddbaa6a402990b2575aac2d3330574c4466d0327702ea0730043cfd8));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x27f0da778df753764b5d349e415bf794bcfc056323ff1b25962a246434204926), uint256(0x292ae8e0ab0aadd03ef961bb0d8289d63f236a1dcec10414417e1350ec052f4e));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x095aab117c8a7d0d7a417014037d527f33c693ce361e2ba1d1a534adb2a9c9bd), uint256(0x1fb8a814d0a35d39009f04256dc3e2ffce6137a13124c2bc42ca95412fa92efb));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x0ccfd68bb61aebdb819fd14efb43960d5eb293973acc26260fc872cd7edfe18e), uint256(0x01ea3bd27a0118611c5503acbdbe341ce6c38380d855ec6332643ea9ac71d99c));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x02fa0f71dbcd64de63f1182badcb7162bf3a23ea3a1e1545534cdb4b10850e8d), uint256(0x21864151239fc904b7f4c63dd966a90dc6731c0afb290e274b867fe6bbfbfd3b));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x22bd1ca997a39e8f28ea67d4e3fc7108479aa912409420621593a2df60021a04), uint256(0x01780f99b78f9b2a8c770df1c710da88e626050b415546ead954f16777649c5f));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x1bf0309696390d642f7bb6a009c9f017ed1db655143e4e6bfa14e5829fd4ee30), uint256(0x23192a675d66482be2cdf3b668d41b3bc8446a7a9c0fae80fa729c5ff6804e29));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x2b48469351f521ab3d78fe54cab3ed9a2668f60b657fcc58944df34f0900af35), uint256(0x298e7775224cc26c70f5b453aaaed51a86553b5904195c4281d59350114ea95e));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x0f1aa0c5cc4f4265c0ae946a9ec3a165f7362fae92018be42f3f8bec6c72f19f), uint256(0x138d520b6926ee76d2795d492901149f4ae735bdad6f4fae2fd2042ed1fff127));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x2ea2ed29c0faa3cd1fea7bc4c9d4f602cfb410a1ebb31ee38ab18a05e72d1209), uint256(0x255064ece70fb394be8d43d70f4558e1a1aac25ea7f0a95276f0cf16c709b423));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x254bccc1279ae996a601e95722d9ec79bbfd86358ff82f8276513dc01858e9d1), uint256(0x2819a0d7df8e917115f5f729b83c6f15be25c0597d8c90d4dc7a3bcf330ddd25));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x12a56b4d4711f027d12baf27ac02164f564e53be29075931c25f0c1827a0b629), uint256(0x1b037540d3228acd30fd98f4a7179f6a1ad1902973f08d256e2c2340266ae28a));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x0ea85a3d9e7bf2e0fdec60801bdf05c0d5709e7fa0b826f325cd58adf919f630), uint256(0x12f5e32c55ffb6aa5ed1bce6d11073fe7421aa84561668e9efe6a78f2ab91b10));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x2b33d0e8f901d8ad848e3ad66d0d22da02eb27144fe49096992ecb0f37cf20d7), uint256(0x2d0566c38421aa3cc955555a94e5c765a967a9123e6949c4e4716d0f3876d9c7));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x2a82ed57565a6106b9596cd5da0c3a9d6c84008d776bdbf54e46d547d8372e1f), uint256(0x2fe8801c9cd8891fc050bf39b658daa93da12884e1c8d2dc1705f823ae03f745));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x201a8dcc4d2202b527452d79855f5db4b76a9fc1593379f78c60da4bd26ae013), uint256(0x2e011d88ef462bf280d49c7b9a7b59b93247e347a684689669813b58e7123cc7));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x20e808f125b25213183ee121d12815730327b234b1612aee608b7a2e5988b4a5), uint256(0x0cd9c23ce01ee4af68a80ce37ceba6db266c7fe3196e1ff286d949d90a7927b7));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x2b9eeef14b55197632b10615dfc2fed358185e1fab17535e0dd8900c3fc89ee0), uint256(0x0f56c4e2bb7c9303eabc0c682af728d6a388d85bb65f71ed66d81663d8ed574d));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x0b336a60a802ee75864ceee19410bd2a9eb2e977f4c69e4ee909f08342223094), uint256(0x101c3d5805265bd8d29f776098c91ed4cb4a53749bb62d75eef726b7f65a7b5a));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x14984cda5030a59666620515563f321eb4341931c557cec03731d53f33bc5acf), uint256(0x1d3c3113da76a9710bd653b0e7751abd7cce3c543e04dca710c8a5d91d22b6b7));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x0a15aada3358242e5cd737efaac0f193e22d9ff1863e6d01256c32421f816424), uint256(0x17d3e493bef8b4bab15a0215147137a4b636092741ca27507ab844f547331c92));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x252f43766d3c9d2a34153dd429def81dd7f116a531d091d3e35224750b814d6f), uint256(0x2deaeef61383f4197accc1323b37675e63c6b45b6b5a1534e9c3ac47d7c4d585));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x16a7a5e1829f3779fa8bee71f69c0c301553283385caad8044d05ec857b033b6), uint256(0x108253012f67dd3c1ae4b324281f8a2e03f442d4eefe3a56c20a1840ee27e3a4));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x141a8c8a2a7807a76ace0f70d8c3a9193f185cdb29ad686fc5b863e0169b1d4d), uint256(0x2783ac75bf51976c336a476dde2062c5c9991a54e5c00a205329a8ad870c470f));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x1bbe984faea454a1d1d48ae2837593b78c96eb2f736bccaf44921e2f97fa75ff), uint256(0x084772caa8f7ee6d32a6b64f7cde918817fbfaf587881ccc5b8ea7c13fb72401));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x06401574c2424efb861986520737f765b8b5455731e668ae0672b1c4fa79261f), uint256(0x1ed5467721ffcb1beecc001cedf894387f2402727d2776ed836cfdee9077cfdb));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x142ef61909b3255aeccdfc135474edf9eb9c10837792d875400019cc48f9b9ee), uint256(0x0681d71ee9d8e7038fa001fd5b2efc85de624dffa5154a8d139a30159d56ffb4));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x0a7fe46c59c55cd883b0b5722f350495a1d8cf5be167295ad7e944cd4c76f29c), uint256(0x2e076a8079e5192b731508be881a8acf1db76f3e750f8530b976ed63e0d5bcbf));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x02adc88d33ede37a221f864507fb4789a33fb79940d0f1ebcf3fbcf488907766), uint256(0x0ec867b4e4731922050d4913fc300632b7158a36a546d5fcaa00c5c47381483e));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x011649d8ba2915ee8253d3c509d172336c6bafedba17f5427da93a7f349dc6d2), uint256(0x20e80f3f314f9ac586b3ce88df959d00f436234e38b33a36a8a76c2fb3a35757));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x2dd48b5193eee3b3c177206258804e093895177ef5bd34da19980e819d169844), uint256(0x1d17f5b4157567523b160b1ead8fd9a6bc42431ff64b129bf692e06c0e13aec2));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x2a8a56966e31704dddc07325185639574bf4880a312f96476f7fbc1819c90c4a), uint256(0x065b086768411cce3d100107d08e3039cb296e86fc0fc83654158fe99c1e9af9));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x10419b2d58c6a7a885faa8086947d75325c5fadb44adc33153cc340b74e6a4c5), uint256(0x05a084dd4e40175765cb05f3a4412a8a71af1838f3704480c96a7c986bd958a2));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x2a1eb41ca69b86290c40cefd4441e2f950fc98536146e52ebcb8ec656f77a196), uint256(0x1dafeef9ef03be3fd26688698bbe970a2c30effe616a92e0c5a590199743f46e));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x2dffe6834c3922471dc2e862f18fb30ca887fcf16eb166124a002eca15d652df), uint256(0x2a6fe09265aa54e2f3a8352d5aeefc652c99a372c1755b27e3e24cf990b0b503));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x0357147e14772d6a9e737ca5ecb15651032fa607d595e4691d167fe80d99a598), uint256(0x201f52a98b0c4af8dbc8367238933492d103c67560596e3de85a97097525a5be));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x13e2f3502ac21b81dc98b5098a08d3c5445ef7ccdbf25d7a04dfd22d640d1b29), uint256(0x2cd06a4094b6101c763d7b6e3fcda2e15abcd17c2aa5c6f7a7e74908f1a44517));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x026c3adf413583510ab49e41405bf09ed1e4ccdbb4dabd8688000b0840fb59e8), uint256(0x18f1dd78abf6ecd558b6cc5faadff5b986f44431e65301a4fe864c0dc708c335));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x1a89baf3a78b8225fdc29fefaa2b808aa577287563fb65b6eb0989bc632105b7), uint256(0x0b3bb94c0fbe42862912eac14fc4c974e0d0e6bfd5eb1502dbb951e849440e2b));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x2a0466f075558dc87b415aa0bd71e8b761b49041c91d92280b1a8b0cf3222d48), uint256(0x1658605390e4baeae5f0727c9dfcbcfe4adb08ed5e2de264c26ba85965f3c295));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x04b6347d8b5eac593609ddc1c8a40851aa7cb0ca9c86ba9fae24b42c556fe306), uint256(0x2a0bbc654e5cca9f48c701b4337432ce922c08a324bc7bd819d8ff0344b82177));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x2231da2dbc5667934413233c12726e5c437d2fa5e0a1e0bafee2d0e57179e31d), uint256(0x162df850c9a6700f836bb053b36741b029c6b9ea4c22de8f3880c974250a0482));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x0a9ea9940a43db0d5f53f374eb3ef3e5b3b2f277c366bf946e571d854e8142cb), uint256(0x2bb0ca2a1f06f502e40d220083e37e2e477b70f2598847d35038e6f846be1fb7));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x06bde97b463c42e498d12300e609a987c69e9b416c94049ef46427cc69263311), uint256(0x0712a2a005bed815320dd2f83de2c10ce22ec0886d9bcc24a220e44effead34c));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x0c40a5f3960e5a543c79b5316084120d404e1c2238f80c99b86ea22d6e44bf35), uint256(0x23a2985ca4aae692a21097b8aaf5aee9388a352275f62b5d37106b299ac95130));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x0d48620fea4e5be7637d30fe75e5ea2dbd80e27dc98a8053457bb69bc5f71c5f), uint256(0x2a14f2f9f3a49fa2206d6ab9c427575c5110b45bc03203a952dcd0516e1d1c2c));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x24b49c2af677c44dac7ce115e46aeedf94b88b694a1d3aa5b2af2be720bfce36), uint256(0x1f1b28ca0b0a8335f5b9d194e1cba998c9860ef84c89eb5ccf06590e02bee815));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x24572ccca3b404c473e7fac6555a25b80034b9e799d2dc41a213cd6c9e9f2aaa), uint256(0x0b709271eeb0590e4ca82cb6f365e63f13b9632ce72ceb0413a3d21ddcbf3bb8));
        vk.gamma_abc[81] = Pairing.G1Point(uint256(0x2d30d36ef709b47c548407adabb87439ced4cdee0317cf49859394fa500f8d0e), uint256(0x0739f44741e7ea9c8dc62a6a10e660708d055c50ab995fe15a6726d66ef7fbcc));
        vk.gamma_abc[82] = Pairing.G1Point(uint256(0x0a3b6ddcad6ca14172605157f2b256836c468c27fb814300fdaaca62bde99224), uint256(0x1b7f135c4dc4e809049be23a20d86c72908c08f398a6b3f60e8c356ef431cc0d));
        vk.gamma_abc[83] = Pairing.G1Point(uint256(0x1c659b6d85faecc923af44b3c3e0247ebf78512500b18cd550828e79fcd3cb7c), uint256(0x156f90ef959df5e06de9244dfe69557c979b4b8dbd8576d2639b3d84e3933bcb));
        vk.gamma_abc[84] = Pairing.G1Point(uint256(0x00d851aefb4ba52611949f1d9ad08bdc1e3e673414cb3db3da68eafd453f2c34), uint256(0x1c1817180a4b2abf240cbd49170f9f81548722a8ed5b2023911a8dab7c571a6e));
        vk.gamma_abc[85] = Pairing.G1Point(uint256(0x146fd825a329135f54ab7be397238057bcccd2d927c1473c69230b25e7f7cdd1), uint256(0x283905f1a9a0d2a491db5f3c5e036ba14c45cb97c008b716ff88a185ecf61e48));
        vk.gamma_abc[86] = Pairing.G1Point(uint256(0x03fe807bb1cfdcf4448bea7a40f2a912c49e49080461ddb98c72ef4f3e141d16), uint256(0x196efab4eb08c55dfd81cefd6b6af5fd6989e5ee7ece862e109df0e0ca808f60));
        vk.gamma_abc[87] = Pairing.G1Point(uint256(0x2fc484d6b9c37a261963fdd5eea442a7afe7d0c66410f8e86d7c229da3deed42), uint256(0x0c69f71a0f8d40cf37092155db61ed00549dbfcf6fefa156a1259108af8b378b));
        vk.gamma_abc[88] = Pairing.G1Point(uint256(0x1c1b7913e5d69b13838c87b11c0d75d331133ad4f91b4cb5fbab60f599a5a3e3), uint256(0x01613b31aae1a859cad2723cc44d392cb197d2b31b717e8c46746944f139047e));
    }
    function verify(uint[] memory input, Proof memory proof) internal view returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gamma_abc.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        if(!Pairing.pairingProd4(
             proof.a, proof.b,
             Pairing.negate(vk_x), vk.gamma,
             Pairing.negate(proof.c), vk.delta,
             Pairing.negate(vk.alpha), vk.beta)) return 1;
        return 0;
    }
    function verifyTx(
            Proof memory proof, uint[88] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](88);
        
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            return true;
        } else {
            return false;
        }
    }
}
