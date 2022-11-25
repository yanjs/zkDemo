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
        vk.alpha = Pairing.G1Point(uint256(0x2acf028285710a75c405d4290982de54d1154b4ab72fc29d607cbf1f988bafed), uint256(0x1a919a2c7f1be3dbec03fd011bba5788d48e3d47eef2a97fff806e57ccc02213));
        vk.beta = Pairing.G2Point([uint256(0x1e5cb2a0875df2f45a0cc4b948f5dbbeadf23a77cd36364ae9dc7981332606a6), uint256(0x064942348beaafdf130049be89ba935a25fb3d9f4a892bd8b18a8dfd4165b8e9)], [uint256(0x1be1965e05b5d84007bc6c148c57ea5a1474516e814af8e2994f90d96f3d73c1), uint256(0x13b5f8c1b26ebd9917a9af06f295beeb876481534f986928568e75b17734e4d3)]);
        vk.gamma = Pairing.G2Point([uint256(0x18bb5c3856f5c6e21dbc8e913d498ae015cad97724b697620e97e5f9438b4028), uint256(0x24cc2c07763956a1eb4388c726dde1390001f18f74effd703511f74b5ff66776)], [uint256(0x1b00034cba56b22b74239347643d01b3f66562487a61fa3e781732e6c59feefa), uint256(0x2d4bf01ccda6956a1baaaddd04032d375413fd35ececce2d783e7fa9adba2773)]);
        vk.delta = Pairing.G2Point([uint256(0x26482e1052f61f9182ec1a597a007cdd9ba8ca1e0ef441fa089e70e2f3a0e55c), uint256(0x0335e85eb174df84fbddb65a0b144ba52523416b666081b7e7221800817d0d90)], [uint256(0x302d098efd3dee4d39778e4b027cd01a277416f62236a128580d52162f60505d), uint256(0x1ef2c3c36783aa906063a237e7b9414178da7ccda6cef0935f0f81d89b6a72aa)]);
        vk.gamma_abc = new Pairing.G1Point[](49);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x1ffba0a187a726ea9fc24d0cb124fcf2be05d456303fe6ef9fef668492edd130), uint256(0x145f01e878335d7b41c798c324e352666c1ad6d64cc265ced15a6549ab22b836));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x26395031155438a662562d9e0d80b3580361a5fde662678f0c0874b94cc1abab), uint256(0x2d60f8cf7b53d3ccbe5a224d51a4cbd21e01367512a202bae15733e3c0e28d2d));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x11eb4b5f56b05f0d63e3c0a94417ac01a22eba2a67f605ad4a9084f991f1162f), uint256(0x06ec20e469b3cbc816e508a5560b687f074d0cf4f9550889b936398d6aa687a1));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x20b0f38b71a58920a70513dfabf6627e52da6e1fc6607cca3634f9638d9a5c3c), uint256(0x0ced7b70c96b4ab95c3ff512f98fdca67de4034a5b5ff27007de7c5b9ed8ec66));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x2e569144fd3c443427022b37f1462ba7e4f4520c893db98ba99d7fdaa9307400), uint256(0x21ac920f1213d834a66b8d8a7f8332ff74734ab04f33155c46fba7d204164b1c));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x2b916428bfcf26ff54dfff4dccfe31531e7e1ee1cd455c61d77d963b6aa80e95), uint256(0x1a89f0e70496ba4b70aeaca346c00ffefe956d0de54dc6a599c51fe09d353fb6));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x00d36570909bbeaa7789f18afd3ef3cca116b91ed455f5b0416b90654ba7ac2f), uint256(0x03b4630a1ac7c8a50dcb91521883d71482ad11d6372afa64b1f9a4892f19818f));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x10662b047d338a707bec7e9bd0ef45a64b938db29f050a832fe82ca141fa8d1e), uint256(0x0cf08e5a390be281f6474325956aaadd4e53eb44714cdb4fdf8d60b9809f9d0f));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x09c9b43e18671c3860250b5a10b396bcb82f22869c3e5ec238ecc6cd6ef54724), uint256(0x22c26f95bd589ea87e57f48915e9d25c850f489c3360f7953fbba941d540a7e7));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x2473a588c178889bd7ee0aa472712bf810f5dcbbf70b5a369571a530bdefe9f8), uint256(0x2f644795dc2d45dc0b77ffc2f11b633c79770e9da93dd0a84c3c3d9d9f2d5f20));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x243a77b907cbb816cc0906057d4f55e9249347317504f9d3de8e079bc4b8e07d), uint256(0x2a819424ea0ba7b762404fae6f54ca08acefc6cbe4f45bd58463aea56126ce6f));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x0c72155a54b2b97b34fb6df6c235016e343c3348a0e8a1fab3421d44418203cb), uint256(0x14440d65a2f6fda5f45b917da6ded5b8674b4ef60279c144f36de9303b254da9));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x2a32feeeb450900d8c6a5aac394cbb18fbebedad3043cece85456f3e00bede8d), uint256(0x0af0f3d2393e24b801b04c98bd9f7ec09ac6e1eb5bdda6c66a3b1923e66b6026));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x14b9e39aad73bbcd45fb0ce57bfbc8469822794e62728911eca22cc0c1a74329), uint256(0x2cf9ed33df14a0b37f5708a2c6925aba001712b8acdb931dcb1e0ec778df5c91));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x28ba978b3d8dcf95db0bb86312d6791ab20632e227036724d9d811624b8097d4), uint256(0x1a28f942179c4b5ef69382234f7959bdf07ee3f8e903f88b2a83acd391bcf6f4));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x151d05b4a29b50d7fb65da436f3df88928314e743b48105832ae75ae7464a326), uint256(0x2aa194dfd0e1e135708bee9ddc49baf1b1a4b2ed5698ee069b4fe4e7a1f3f5d9));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x06bb598e900cd3ae3df851af91ce2ab268b086e377d0b75c53b9db7cf8089cc3), uint256(0x0cb7ec1dbbea02b1b36f3e89f88aae689e72891d5bc1d6ce51dba5b3b8295967));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x23a4938f1f89271d8a268b91f345d731e749834bdfbc5d4013bc20d7e3ab3a55), uint256(0x2314e506e14af3f003d30d303aa211b0baa5a6cac4058f80bd16a6d86ff6d127));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x10648875d12e8b65d413c3736afd71d8283c8bbcee7465aa62a27e14522fc439), uint256(0x2e122304ab940a350d7f1c83d4b3e857d22741e95e1a29ad680dd6d25203f13c));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x2d86ff6cf0dedfa8cf487b301768462bdae77e7c91b9898dc19cf660e1358229), uint256(0x14818927df7b8aca0058a0729482459cf94fac95dedf168d20e15efe73042798));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x2ccb3f53524b39b8ffe4fb2ffdb77bf2008edb0b7512e3388eb0040342bbbf9e), uint256(0x17fc277ab9e64d2c60fe08c3429564b495013c8d73bd378ccc391f8c1532f16c));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x1b0d0be45e5dc707204386669799fd58d312d5ac99a64356a083babf6ea31367), uint256(0x24f2c98532c25a86b706d21e9035be83b7d909ad4e3963045273bd8a35166944));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x0b3a0ac41501fc7d6abcbda1117e7039f660a6ef7e0de91d3551002e59da83c1), uint256(0x1114edc5165ab37685442dcc1fa7b394e3b4f063249e085f6687e2b0572a9222));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x1a9037378dcd55dd2067ec076bc7bd60e3741ddd05ee1b38dce4b88edea8d87d), uint256(0x0c2773c02e08f34586d88b3d0aec38a7f6c85e70f477178107f791bee28099fd));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x136c9ecdb692efe5dbdb1176da83ea9bd9994538de0e4aa5982a6567c776bf47), uint256(0x11f639e98df68902b09781efe8c109e05d426a3a0b65bc47415e6783a9fbb6c2));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x2f764f4e2c2489cf1f079cfdac9a9cf9c34f1b1180434de1a6eb7b0ddea11c73), uint256(0x2713b399fd4d4f925632efdfcf0fba4cb659be4324cc60d64c1d22a1bb8062dc));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x1006629db851ef4a4394e1bd80e9f4f4b3cd4f644e55f6a56dab7789dab280f7), uint256(0x22bb5c3a79ddbcf138165e5a51a05ff8f729c14035b830aa5236be6c531abe44));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x0e19dc165cd8fdb16ced898f6f606d76f36188c6e70ca17fb5297bb62ba17556), uint256(0x1c13aaa9d8f705bc4e1a51906d8430815372b9aabc3e9f5de8b2a905e563a93c));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x097f8237938446605884cb5ea8ccb6ff4c572116aad52a03dbdb1fb4c49adce1), uint256(0x0b6ed70ea52051bb64cef7d2ba898cf63e4b6124c7ceb222aaabb3d67257f7cc));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x2fc78d6e7e8d92015627da1593eb9111bca907790f5a411686f833f566f364c6), uint256(0x2cf08e19d6a5906c790c2ebabcefcb5960778535a17ee8584e85d7d3c9a41a8f));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x04f2ea945504cd7a35be1ee5182d1adb338f49b3a888f6758d67f7deee7c8633), uint256(0x0efca2238f9baf13927818f64d27054762b35f1b5b9565e031f02eddebbd09e0));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x0614b50fd8df70983239836cb2dd6ed1e7cc238e9ee6a44d7e96aa17d50ae78b), uint256(0x0de158fe3692de7a488bde5aa396005f03fa74b8bb98795e01bfea3e2dfb59b2));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x087e7067bf385337a8564bcdd751269a4891cad2b4abfd0d826d8119a9d4de85), uint256(0x05b99ae6419f3cdd74f020524d542ffe6d613fdb38f731acb726cc9d4b47c4e1));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x1fb82cbfffce925dc253647a9450b1a885c16e263750d93abc5d1ae3aadac29a), uint256(0x1b70d03cb057c5ba95f32ad37a9b391ee75efe0bd47568aa8a22946cf1bf9837));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x03f4bb301f9f5edfe04af1d6793b4e25b2042ff5c9edff9e993f1266455a1ff6), uint256(0x04885ef6c44ae9c013e657a31eb03868f131a0ba9d54bd1b8d4f40e5287dc328));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x1d0dfbe4c8db96d9aae416f413a42813509edbea7291b8b13f3cfe788afac332), uint256(0x0a9cfd0333cc853a94d1ad0e5b46ea7cae53b33450837ab0783ac176ef7e9402));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x25b0f231059de94a28a998890ae5198fe74c71ec083341e5e2806709f1690204), uint256(0x0343956e416584b7756a57467d30b12e0a433cacd756b4810aad26a7e88617dd));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x11bcd577ee1fc6b72d88767cc72cbfb3b24ba5db68b8d6e002dfa2f71742e06f), uint256(0x1a40343e3e2125b8e20d43061038aedab6f22d5e2f848c802e9a6ca5c3f9136c));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x09652ae7dd5e186e545859b4e22fceb2dd179820cda53ce89368154c9699fa14), uint256(0x0caf637ae5d8cbf14e84bed922aaae8ab2175cbb8f21d95a778f008ca4816d70));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x2d70d4feadb48038773a4c3fa6f333ae4bc5c8fdf58b324235f0d58572d671dd), uint256(0x1597f4938b99199060d092e2eac7daa7528da3a042ab76bc1a00956bd5e5f860));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x06bb626b7f44a503e1829ce300400ca947888232652eff6779b8eb16a1e1cac0), uint256(0x15b8579221799da26b75d458e326987b631b7758296d897cb8dffeea26bf4611));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x2463cab831c3721b4b8fc3bcee8e74d5ee5606271ca5daa07a5a80b310be8d16), uint256(0x1b9232ab81075b48040afb2031c3f6cdf902932736af9a5620f3d61c9940ba62));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x1be92c78c9be762dfe8b8986d3131abf0ed11f4f7dd27fd89c556aa14b1ed29d), uint256(0x2ec35f89346569048433320968bc75a964aba593927cd8e2b701d8099839fb2d));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x0b925a1b9ba8b9927fc092b96f39d73ff15cb9b35cb73bbcccaf229cdf4ccb8c), uint256(0x2621bc460b5f2fef03ac195c90d7216af1a1dee5c9db38d04a00f340731bc747));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x22aa5c116af90e618c0f8291ae1ae17a762db7640e1f0d4116c29dd4860b4fa0), uint256(0x22fe5e577d59412bb470c736f17c8711ee794970e385352da6c03ae1c3429e3f));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x099d25ed4a1a3544bebeeb24c4e42abf4b5d5cba3b267a875e9cc88b49b1ec0c), uint256(0x068fcb07bce14e49f5b4bcf0385ec350e857181412ef1cae0e50f6a0c75e15ac));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x09407c409792734609e419c8a82af34c493d46a7ea99833ce0130dd2333e0ce8), uint256(0x25d0876fef98423ef3e88153a64d06c2981c0d296aff9b20277679bdd74a595c));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x02b9e359e884d81f65e3fbff956b6f356883fc460189bb2ddad1da57fdd21abf), uint256(0x20ff677098a63a30d1b2d520079f8470fbe0f8d44d936f5aa94d487f5671dfda));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x092fd28d3e9bfd120f05335a8afc0f3c9e17e80aa0242f0177ac902658cd66a7), uint256(0x2b255c82555af171c368e766a738aa191b38f17bdc1de0ca0bd9051d0b805d9b));
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
            Proof memory proof, uint[48] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](48);
        
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
