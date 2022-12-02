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

contract MergeVerifier {
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
        vk.alpha = Pairing.G1Point(uint256(0x04b2ffa9bb75dc856d54d15d56b98e4d6c6e4324c019b47a4faed268078f1af0), uint256(0x082245e79e9983b1394099e23cab076b2bacb24a4a32f04cda0654b1a755f870));
        vk.beta = Pairing.G2Point([uint256(0x203e7b3a44ac25ddba2d377b4514a43a6032a47f432b728de58f41b4cad047b4), uint256(0x1ce154c3a8318c0006d414702f8251d448a04f329f2fa4b10cfb1c96b5cf077f)], [uint256(0x2fbfedfc806d385dda32cbe21a6fa08d63eb850788a2b3f6295256bf0fe01187), uint256(0x111f9c9c685b414985261302ede38af954ca02e5c1f367c1884f160336f1a047)]);
        vk.gamma = Pairing.G2Point([uint256(0x1cebef9a5a3648c08418e6acfc417b4bb9ea873e5dd334fb868739ca81609900), uint256(0x13caa47794339b97b70c319af54b1d988ab05ae8dd3c2a1ad830f70427c178f1)], [uint256(0x276c1045f1f796dac68e2a69238ca5b32eec931c2f977ff1227c1f84dd43fb86), uint256(0x0938ed27ba04c186e1fd89990be19051872f3e1447eba0c9c91835bbfa13a404)]);
        vk.delta = Pairing.G2Point([uint256(0x2a9c64f7c714ac6d62bd6d42cc428258715338db2cc51d40a03a75747aa1b3ea), uint256(0x074c7247e3a9665d2fb3ff080fdc90a62d28187f3ae7c8711179e4b15146d95c)], [uint256(0x057935e90639ab0293f33c34107c921d38fb84a2dcfa8d37c14a1689f34e49a9), uint256(0x05e0f39983c019d6ea532e7f60b45322edd801cabb848c09f2f3eedf47737aa2)]);
        vk.gamma_abc = new Pairing.G1Point[](81);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x2e03d2d76e511331a1c9f23a4f9679de61de4a22abe5425ec4b8e64b8a1a4b22), uint256(0x036b9f32063d7fdfa84232c03a0aac02a5901af84d57076ef5ec6215e43c13e4));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x28c33011e9c70a7b6585f883cde6f726f58cdcb40d485442270ba1b1102f9e1f), uint256(0x163b731e9ebf359e985292ed708418989b67aafbf6e7bbaffd636d71d21c22f3));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x063d7d4b61ef5509d1645a23d6b203dfaace0b1cb3e236c8cf82ff89487a0ca9), uint256(0x0027429f922e3a4cecfbdb3d71dc32fd8135efe99d79f91ce14bfcb1f2fec48d));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x2a247cdf5da02fc1657cf6a59f704b884fbb8703403bf4ed847a4716e47e6d8f), uint256(0x0c7e066c7eafc3b4ea90fe6099dec0eb3a4a1ed98cf5e9d03befa31e632cbc26));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x15231ee681fff0b4a485bd02678b040e5977e2682cf26fd57c88faf40e3e2b11), uint256(0x2647eba16cde1245a9d43f15b14241aa3cdec52f4e4a1444558c2130af6bfe04));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x06ee0a62a4ac92e17a9ca022d676b443f9a9aebc4262c7bbbf5927d4e97d0054), uint256(0x212b88b6e923306ffdd75bdb8b2441e3989c8ec42be4c96eee526c5af7771754));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x13e1f9e3221084f072190eb349dfdc0cb5862b9af6ab5241924fc586a09c2ea4), uint256(0x06619bff15eb9110db7f566ad9aeaa439f7705ac99c274b7f0d52b90b15a8232));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x0959eea0edd1166b488217a30f8c5ddff4ef052a7974f0e14149fede5aae2a23), uint256(0x2542c6e8959f5c34938e0f75a0eb7fde8dd1203ca438cb97aacd7bc1e44fb13d));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x09947b6cc6564adfbbee67c1151eaf336ef04376284ea7b957d14f06940d3770), uint256(0x0ca2a4d1498a7b63d55e4abc2c548a7438dce1fda301ac491cf46b6d0812a98f));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x2e6a01ed224b66ccd862b283a611bbc40da44794189bb7695b57f165300ad3d3), uint256(0x22dd46f852f5dd97cbed583fdb8c2c506ec2d35fab39309cc1edc16aeda89fb7));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x0252de592e64e591276bf5c230e9bbfd5779a5d60e46810c9c608e486325eb09), uint256(0x06bc575403a8d7565cd380dacd96fc89344ba53e022f071e1ecf3f1519c5b326));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x29887e4d633c011d3543df52e68d7bdccecaf283d715473f0f8ed6940b930d36), uint256(0x1495af20086c007d9cba3ec81a935c7470a742c9417aeb943558b927c37ad711));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x20bd1b51c7ab4dff0d41f52e24d2ca3e80d3912072e5d746f746eaeda61eec1f), uint256(0x0e59d78eee936cda52c8aa532484ddc598f0169964e82246ef34fce498f71e97));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x2de11419ba6531766e26bf26b118b02bc284fa9e457dfb31ade2b8fed946f980), uint256(0x050e81fd975868dc1f45629b9bdf41e65e118ac9f3c48f4aa03469e1b7ecb4a5));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x2de5f945887ef6eac72966b496c7481ee2ada1a0f9e7fa0dbca7b6fa0fa03df6), uint256(0x0ef90e823daeda5de26525aad42e2651c72ef77d6b274a1cc234af92dcbfd089));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x0be75cec2d699cf78a0ca9fd0768ee3e4945d53d17b63728e2f7f3224acfb52c), uint256(0x0c27a200f3a1ff58d1bb496885e61e62ec7b22d6f0f6fb80ee35e4627428ebdb));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x23b57eed0f0a5f6bf3177acdf70e84bec299a309cd5d5bc585011f8a515b46ce), uint256(0x2ac03ae4f9ae0038c1e90cd1cb6e15e1f41201d5ca9807261412be81c793ba1b));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x1f107d69c228209cdc4eaf9399ddc39e23ad5df68a5c0015681d0572db337613), uint256(0x1c18ca371e3b5c051fa7c15ad71dc95cd0c3b4429aa4bcfb34fc7ee85ad19ebd));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x0de718b3702c8c80ab5d76ed58d8aec6ce064e110f5c999a6d4a8ed93dbe11ed), uint256(0x2827b69fac7f4b10650f38ac120334f619123bc02fc54496cc7ce65849ff3a2a));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x07139a923a4d3f39ac7f5be63ab337f54057c220c62c3b0cf66ce9de84d660d1), uint256(0x1799f918aef1b17688a826debcb63bdca10f9b3e8512a6df2a924a22163b0a06));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x1300a9bdfe871765c41b23a19b66376960e0c5f27b5283ea474a5e22153cf2cb), uint256(0x060533c97646396bd9105f7876f9bc4b1c1b6974f9621cc94b494ed380a0735c));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x16821f15d3a45b4be96593aad9b31b4f956db5200be306e595d2bed439001bb5), uint256(0x09410ee48e600b8e00cd08cef1ffda78b16872ce6700329d2e923180031f18f9));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x03291e9165ed0732b12e8afe19e16b2e55793c666445cfb9571433d994c28bf6), uint256(0x24658e711dd8b8dd4dddf3ecc2043b1af728e5994368305f3af239d5743b20b8));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x27d5b3288592f0b156f13264d17ce800d074ecf80b37f7c555f8a16db5d1a72e), uint256(0x0c6bfb253ff27b250b30c6dbd4c11b641e9bb58e8641c1df2cba3b5166aa06fb));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x04f9abc0018a8ae53ccee9b7dfec62141444ee6f19903557df3f2540d1fd53a1), uint256(0x2e191dfed9b3251ddfe9ba294ddae9c52e7341130b6cc4c172d3aa1ee933f892));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x117e20ea69c93e185632c5c8e2f846dd3f5ba79daa6284b664e13fbff33e9a2a), uint256(0x277e134f775c418aa455099af41753570d34f31c66628b52426f86355b17f0e0));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x212cbb49347bc3121fef9cff45ba95a0c6d432e69b2c670017118239ef580927), uint256(0x26260983a970e0385b488c191e5c9fc1f6b55cb69ff67a88be01260ab5e82407));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x1a494ad275794ceb0ac50a38dc7d6ce0178eafe29fe1d7d5fae94dfc8778e1a3), uint256(0x01735f915505d1d01307051dd3bfe158e1a2e7eb9491f72562c8c29f5c048f62));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x2fc4c11bfb9dfd259ccc0820f1bd0fd684f99156a2402a25792e1c80d1d0dd56), uint256(0x07d9e238ddfe3ae2fc778554a729b0ea1c73f962ee84001568335201fb7fd51e));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x2f3063c093ce091bf54c842e57faf1b95b0de2a79194e9143ee94914c18790c4), uint256(0x2bd31f6c7d970aadd1aefc844c2cb2831e1d6387fe5c7e2e1ba39163ff0f0be1));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x05f3aee5e1e50fc02c26009467c2a08e1d47223c80bbdc7a5d776933fed2a117), uint256(0x282244c6944826603f9f431e5d09a66f6eaa948fa9edee75b4b95785739fd4db));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x11092b733b27ff061fb5de42d368aea5f6de213ca7048b2973a75f8c07ee832b), uint256(0x1a2103bae29cd097119f789c7c0e5d66d45b181a0173e30da7a7cc227ca70d7c));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x02311867c3244b4d31e9147a5fa7907ca00408de99b43327e5b7262291a92f59), uint256(0x16ec5c8f09b943fd8b15102f183ae47d2dcf3a908f6aa46ab6ad59ae7062dcfa));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x1f98d452bf3c54d523dcd66065501e9196b41e5a1de11c9335733fc7b6d147b8), uint256(0x175539235a2bb0798e000b9cc2a5cd4fbf4b219ebeead62b11f87182c0e24a66));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x0e58e5019c31823f25d7d33cf4b6d4ba8088ae96d0e282e9ceb2bc14135bc11f), uint256(0x29c2ada5f8d44ed0d4fe7270a4a149c07940a2e839698b0238cdd0ab2fcbf35c));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x1a7e6f5b4a5c204e464e84d56ae202ea397963b0500c18fcb3504d2d05fff49c), uint256(0x016b6e7d1d56844b2f61959f6d95c701d214017cabbe188b421d8d24cd1e655f));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x20c2ec925449d32d012087889f5adfc83ad2d13541fea98aabd85c1bb7f3bb21), uint256(0x22a84d6574b213aef3deb56fa7deeedb4682154e82763220924c2f51b05e918f));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x0b99ced417e4b4fdfde7f2353fb43d13dce8b8ba448e3e5432180dba0a6bd872), uint256(0x3046f3569367ffc19f06914d4bddc51dc1389922ec0b18f9fa80c8806ac982b4));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x0063d471d738cad169ecf3eca5e743ad342a9bd135c8f7f952432a803f5d435e), uint256(0x0b580348a4149b75ae01658f0c7add7b78734d1b59f1ed9d8aab31d3d7150398));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x11205d88dab340f2f8578807a022dcbfa9f295bbed65819b76362a82c79e3eab), uint256(0x2809f6af48f785b2c047a36adff8571772fc2273b6111e5761790281a532c52c));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x29a0e2466bff9348e8d683d180cde469700eb49cad8a1f6f2fd319b64048b32d), uint256(0x05fe1201b36465ffd0d335762f95980186d11e93336f88f39d70aca444991ed0));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x2fdad48416e6061f5302ec0fe6c12bb18ae600fabf46ae510280f55394767b8f), uint256(0x100a171db075b545ca6ab5e0722b6d9738ebd8042b844069351ec80df1f8ed63));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x0bc2c829e5e92912bcbbceac1b913a873f18a36d557c35a1a370a2dbb6fe6085), uint256(0x004ef7481237be021b5406e71117bde5845334c742007dc9039015d02d04c254));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x03c601ee9f49debe4203ef603bd7a1ab9fd7f8499f47c35eaf0028804d5de0fe), uint256(0x25510e42e5db0c0e9f16ec5c5f58899c53335936d32e27504b656c2fb4db0347));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x191444bd8abc759cb9c4e91d56ae43d63f7091abf237d77236c98f63b150ae49), uint256(0x145846301acb6cebfcc084efa457e2a60a2a7e04288774d910b761e52978b641));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x03f6b6e97e3c81251c353fea47d84a79f3b54c0ff4ac99b21cb47f7b75f7acf9), uint256(0x2851f242960d0fa82b9f1f4d1df06b7b4eb137eea485299a2766350f18061c7d));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x2d6a10b1dcbe5e8ae6eb023481780382ce1dfe458f227fde07fa6f0202c699c3), uint256(0x0048ea423e891242e8eb5addad693186a70d51355c3205e0b5adee8822f6763a));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x264078ff47e3e8da8ab855b1945fc879d84e3b7e5e5f907aa4db315fe1b4bba8), uint256(0x0ebdf451ea835d5e980f35c1e3866d8d8be46e720823b5e6250744e7488bfd68));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x0278d51e32f0a19bda22707ce884d735976764aa185c10bcc618345d64c765fd), uint256(0x022f54081e90593b32021acdba9e7afd0b09c474a62c576f25c594e4b9560af0));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x1ac541fe060f703cd541a5bf81d23208147e66950f9ef62b76c76d0810496dac), uint256(0x0130fc1d6505e0c4fc98ff459bdc1c3207ebab7bfaf29fcb070b4cc3825445fe));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x2eb4d9cbc476f81717f7331c5bee79abbcdf91065b886d3ee70bd52ba7fe7a83), uint256(0x2a86d33a4f8478042a98239a468a7be56122e2ab7b7f372915cd8b3f4be2d6d3));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x032286ab21ac93fb090608b3354f710fa60fb22432407e480c3cd7a89746d0ff), uint256(0x2b5f5fe258b3946bb60591ae5421533784e950f9058b2bb48f81069deadb4a86));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x10a50d230721dba7311f8bff82dd31553ef7c34e320710733e4ef3463139bb19), uint256(0x2386fcb8506db9a639a189d43d171f518089e66eaa66be6efe4f7a41145ed49f));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x049e4dcc0f0846c85003f698e6da194a7ebaa8df0001d4c96f0c25d172f31a00), uint256(0x1adff68113996a44df35b9ae2b60aafda907ff2e602117a08b89f6682f926a20));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x0c92b263862f3276d70e74e2fab9ba9b5617e7ba6e56160f11a94b586fb0bfca), uint256(0x16ef294ad5310e5dccbd581ec95a281dad9b31a42cbc0b5d8964450e0ad42060));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x1401b2f736d65c38c13337285156966a605e48dc16f1b6692f2551dedda67c19), uint256(0x2ef8657887bcb336dafbc8f01e785a22ef2bebf7fb36cd606630aaf8c2543116));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x0a9ff49212bf747cfda4fd0b1cfe736d519293dc8060fe3c2c758d7960f317d8), uint256(0x1d6ffd7ab56efd44d7e862e03df08e57f912eba4f752a7bf454edf699781385c));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x2e034552992b75011c0fa2d2a7e485e7c107a451a5e855c58008b1443be0844f), uint256(0x14dcbb9b17dd9949f540ee0f89d0b860407a65991dfff99bfae6b0f66719eed1));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x0742252e1fb688389fb20cf6994d85a0f5ef0d5227f45e4c7d2596accb3b655f), uint256(0x0b1c7aa425f18875fa5684658c223be4b9e822b2ca228a5f455510183fdf6a98));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x2e6ac0efc8e6fee6bc95ca69f49e86989bc9c6e293f87d223e7a14faff58c5d2), uint256(0x0a37f3c95fefb7230699530f9c2b2abe51cfa936795c0cf576c93d8ed39e57f5));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x3027cc41465e5ba5ec8bddd0a6d991c1fe892bdbed78d783b3025fe0a27be139), uint256(0x2ab3d8080b4a847fc7e78610235ee856ada5d169d375eb28ec58a5c1aa608adc));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x0910a45c1c79d102b9933d82d230ec349530b0f452a568eb97f26d7f47d6338e), uint256(0x29fe410e51a2ea9b6488c0693b5ab8fa2b3d5ee45440a68c0436a0ab450403e6));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x26749be59f1d05ba374726a4c18a40d529cd53d9c0ab87efb698235c24d079fb), uint256(0x1a368662f4f0e4dee799e8f88e66145b4d26d35d76f122e063334f47dcdd188c));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x2649225c182ceca8715ccbf00d0d93087e96c964aef7132b6994eb4a1efa0b53), uint256(0x018b1fcd05ff3638ef84eff1715aa777bdc6111d97a6b5dfac1adb13174fb338));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x2e04b77806a8a42a53c31ea753b5d75a42b00fd208417669cc027690716349e5), uint256(0x14f9b518ce0c77f0534071b351e8a785004f253a1cd9853a5981c0e6ba46094d));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x20da0176641fa5fec45d56c42979b85e816a1ceaf7d9db3b20f33664294ac4b1), uint256(0x1a88930177f5ccb810df23e12a5b5e373d404359407402d46a437d369708414e));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x2032e024078dd541c1286c0d4f5b1092be3a639e81b5d534b3d864280685a27c), uint256(0x0a439185bc6c490015d5585d42d946704431f925e783c4630f9a3fc0586cac72));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x1e849e71e63809b7a5121de4bdb045c83f7f60a653f73680f46955647c31b962), uint256(0x09af7d011d0f208b81914871da299dcf1f089fb754e434db2e74758b3c9b3cc5));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x10f03644870d9742030d4be07698b1d22934bb1d47ae4bddb67a8e57c9710a41), uint256(0x0ff77eca043b8f54775d7f89e5ae2fd6df2259889888aec20577c1c1a8f88794));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x1e3df3fae37cb772a1b5b96707fa1ecd4947a105120e8b967486f94aa4fcc25c), uint256(0x07ecee0190f137a02313bda5e8dba094f1234f08b91bc6cf2281868bde86134f));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x2bfc73c2434a57e96fc2ea146f39f3e015f31e63fd4366132439432a0d5e8434), uint256(0x17c47c2d8e579a6377598abbc1f4010ac015022d5dd7624217ab8a6aee47024d));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x138814d66418b733b387513ee092b015dd1741ceb485f32e3a02b86427a43c53), uint256(0x145af3be42375ea2e204b6a662d1885cce9aa514bc0a416833bdca0b1f9027ae));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x14a86e8a582a43e4d8ea6a8d61ef15964da0b6da30c2ab73fa983a58350ccac0), uint256(0x2ce913145211e998766a99ac31e078fcd13435597c54c5084b854a6a65ff4832));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x0d066a6fb9c2a1d40b49b013f3060089287e4802c60ba9e689ae654dcc6b08da), uint256(0x106c93168c86566542ead4edd1e177dc3cb785943551c0434f520b6aa2c8350f));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x017c8e7fb16e2457e6121aa3ab76c42add81fb964253a6047214cf407bdb8214), uint256(0x2cb409c1ec266a037d58edcdfdb2265d78857d5b8a1b5c298002e8a7accfb92b));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x11eb26ec5fefa793a8718c04e485d093661129e6bba9a17bae9687547b66682d), uint256(0x1f20b55e9f32405229eb4ef957f59c4e6b1c3bf9a8fa62f8558ffb43e99f533c));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x250aa4007cd38917035ca40c4cc3ad129df4dd0b71867113d738f00cf8b22c18), uint256(0x12fbaefcc8a00999425a34e128c9daa47ede98a3286ef6b0ce61c4831c9b78da));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x12092a281924806b3d66a9a805f0995a539f4a9cc9bb5d2ca9a9e4d043bb96d2), uint256(0x2150f87821dd3b0e52067a0067329a1c92bce65563fbf18f18375923cc58600d));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x1e77fb2abc9ddd17916e367601b55d1b0e7bc1a6b41b3560102596698f90af0e), uint256(0x1171607920b0c12431c46ce16cede331353de26e64996e81ffc4cbfb76763d25));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x20b0f2f27f7bb9d1a1c1ea34d2120e343888c1c5bf0b4a1d468537dec88928b6), uint256(0x2e7b1b237d678b66ee4db6ab5eb013473e55877b8a87df3097f3d56fbd8bc4f8));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x0a774c5328a05ba0dc19b52e2ef96bad3a486ac72ee981746b072096b54abfc2), uint256(0x2c01b3e06024a388dca54a9eb03a466cff049528e1c99fb540259e725b75068a));
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
            Proof memory proof, uint[80] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](80);
        
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
