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
        vk.alpha = Pairing.G1Point(uint256(0x1c8a88268ff2538c6e9bd824ad9f5e2c448ee349cc23b9333b2bc74d8468d0b4), uint256(0x2cedb802de080f3cff82df62a3d5a28b004818cd111ca964ea96bb539e88b703));
        vk.beta = Pairing.G2Point([uint256(0x18cb232861d4a7ff082e5bd502165455d1e8863652ae95909e02cddfc0721a2c), uint256(0x04c6c82611afa9e96c92ad9629deb0878fb745192740ae4934dbcc681d426279)], [uint256(0x25199128efaba4d88d735e57ec744ee7fcdd64dd7b60160c42a0ff06c88e41ff), uint256(0x1605ab9c1b904c1664c1f43f6f1f547f010c12fe49cf85724d5d0db1d9a66df1)]);
        vk.gamma = Pairing.G2Point([uint256(0x1978486b0ee61cc4ca8b9f607aab6d440b407c3806bf76daf8c09e63e2a3adde), uint256(0x0585ba445819814e4b84425e5a1b1b44b516767c32397f3cab6471ef874f4873)], [uint256(0x0641dfba692e0607e929f028b82bd61bd2dfff5b02c33c65e834201af3a6ba31), uint256(0x2f3ae60dc433cdc208865bd58ffb6134d4ce1948d6f9eb31553b5028f6c4d21d)]);
        vk.delta = Pairing.G2Point([uint256(0x100502faacfc914ad79648140446cdf7391d4b3b78ce4c1828dd9d2374172bc8), uint256(0x0e22bbf96ea145a414556366b71cc600f47c836726dc15f5410a62d88b7c75de)], [uint256(0x0c8bbb0c99b5c111dbcc93b9015032e7bf6d1adc30648cfbeee3172d7e9f5471), uint256(0x139ece16b42e1e7676239074260c07ca28c2198ae10e2e74945ac1822a851e6a)]);
        vk.gamma_abc = new Pairing.G1Point[](49);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x0b0a1abcae9bd65dde1c8793348b139505d213bbb073186ffcd1d6d07c7ace0c), uint256(0x13ea4f80040d1d30f0ad6c76d13ad1a5123e64818c5a039267633956c92fb12c));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x2a47af5a9622028f9e9bba9dbb9259cdb358d077556fa7b3298878262c6567f9), uint256(0x1f10be4de59e54bcedb452291720cd723db842bb72353f519b9f8bdbd1cebe22));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x1eb59be59d59725571c14273b4a760b400b157fe71dd2a59c370901f07c30886), uint256(0x2925d4720b5c2ab92eccc4070eb29a9c0908dcd72ccee4e4d68b8c9cda25843c));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x17fb947b9c3cfc94e6891775d3732667faf2a8fca71a51a4765cd1a47984a53e), uint256(0x0c12c804a0e93dd67d79c01b5b0e1c6516f0458c0fc8b6bcd709ca1b32da53a8));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x15f5af1d48d6f5f45b2d32c6a937dd8147c737901ba78b0f300513b6fcbcef57), uint256(0x21615ac68b42d8de9d162e10dceb90acd406809075de049297a596b9b3c56764));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x29bee95688daceebea69659d30425c7734618625eef8f0b81e11f5a4b568d252), uint256(0x0103e144a91f31bb4dde9e68b4bea74a84ffcc8fe47dfd04efa8d3f3005eef09));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x162e860e3ebb555d8aea3c5b0a6c1003e6366d77b92a8f9bff48a7bf1b27f15b), uint256(0x15d68facc7898e9e49787fd236ea51f37a5d2e3200fc623dc8dbe3f10a032aa8));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x2dd167bfe447b3328b993764a1cb973f6117a886e4347790414e478cae91b1f1), uint256(0x2eef789a369857a5fac1f90fee863250b5e837c873b2363ac997eaddccd4a414));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x29843ee1becd460c7a6060bd57d81a7f18c61a3c79053da1c5954cac2c8827d1), uint256(0x032faadc4126551af83c63c3e9939275c2bf103a651f0133e7b73df2971888e9));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x2ee60e5bdb686e616e2abcbaba9238fa395e62e336f126484ec2c1dafb823208), uint256(0x0ff0573909287cc6313465facabe0ef2c57ca3db5698c97c7ef59342fc94417b));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x11c04b54b4be7d1d940509f59f11f03d77dc58ca3e4243c82ef61ced63fdd05b), uint256(0x06f76abdabed57cc3f42f33dcf611b9cd5e39661e13d272c2d1c1f557b18ddaf));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x2a2a81e09154cf37336e94b73b65290f4788cc3c10687e656982ba07da68e576), uint256(0x174a465095a30c89ff28ccbb86f99f4c110f09ab349c4e3ff98f7a668919e7e5));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x032e52dd9ef48c1f6645520c41498127d7166a8b8e73ea48075856ba2f18ab8c), uint256(0x003d3121ac8c6512cb825ead03e6ece5d6ef51e32c2f86226845f2df511898e9));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x2c3c2888714bb167820f4bd7f7dfec8df9b2109880d0c02f63d8397c4c24504a), uint256(0x117bead324b58a13eebf6e9780454c20015dc02ff2ae311a4b2f1a0e908f6b4d));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x1005cd676fe7a752587cc89b955ab74ea6d91851b9770ead137337c5447d008a), uint256(0x1f009e1f92136228f03da6e08baee336804d3ef292e5cf5f46d089f7a012d296));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x06ff59e5bb62f5902d372bd5d77f5214c7c93a7fb9cbd0488722ff944dafe3e6), uint256(0x294e023bc1db0c00aba5bf9ea9bb72d70ce4c8861b027f0f926ea8ec17427075));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x1066357d018471fd124d6c7cb459fff43205b551446172c199ce55d2fd45690f), uint256(0x2dd18647fd569e70a14aa1ee9573b49454e29bf965442a88c1f54897c735306c));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x06f974c4ca942be8429c0df59b073c2a26b54262932f87ec0b2d562034ef2492), uint256(0x2b6b75e9fb77e02b9a908cecc8d13a5be1ebafd1b5152515f9ed7462609b11b8));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x252eef2ab5a842360dc72d3859bc151302ac2019dad687af5b1eca0ffeb66e87), uint256(0x25243d247a109ac6f952d989ebe8e9e244464f675ecb24f07919022533737b9f));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x109efea096d27ae029334e3b08b501c994d259da7469e520b4fd20139cc3178b), uint256(0x0fb87fdc13fdafcefc811b82b6c737828729ee434aca496b3bbb6eac6babda2e));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x00b337856f7c030bf6f46924a8aeee199f4131b8c2124bb70f5547d4dc53b4e0), uint256(0x11c1f979ada5e750a36ec7d9a10d9d0b67bcaeec4559de868b7cf670bf03914c));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x0aeee57aecd176a6f41cc0811adb03cc369589e35aab5e8e42778a0db8c65990), uint256(0x0a1bd29d17db49eb724fbb852f2fcba9ad00d734975da5e853dcaa124a25d946));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x0ee5e5982a775b4e2d74270cb0273f65cde63daf6b884f58415816a07880ceea), uint256(0x26f49918353e282bb19f3a213313d8b316864c1ba6b54e1d5f919ac5879e1e99));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x04b628af9f020424c38f1761ed0faebd3760138cd1a067c12420c77241286d85), uint256(0x010b6f5704818c201a4eee7d3bf02db658bd491cc2f4548fb103031b239ad8ee));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x2c260ba3999ce034976a73625db4d31b82511881975a17ae06d442bc618b55ee), uint256(0x0e163ce7554575c62058ea0e8252fd7a29cc6e10bae2ed75b6512391e1c62c0b));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x129eb09c62daa1492ae91ba4fb6902d36a9c38168a51b18461a907d2f25c722a), uint256(0x053ffbb84094cfa42c0357cb490df221d93cfd2bd2cf20a88c9c01e09997ddec));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x10f3c5220f8984d622eeae5c5654fa7f7552dad1b85ae9bfb9b2c61a934ac844), uint256(0x20b13c2f0eddd4c5dfd1693017f690e88f747fdcb1d2778ba41e67de56c74aac));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x1b4d0ff2bd66b7997699c23f34f539a8f60a85657b6232891b913ed212a9642a), uint256(0x2d5aacb5395beca5bb68e7e8500b86d7597d79a9ba86ec2e11eac460aff8ad08));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x08e1fc0e94b7dd94ee0509695e3ac1e651c464155b6c324e24d1a494ad79aeea), uint256(0x001853a2a0fb71c6e1e4fd24123207bab71a066f532f2f351aa2dae0c6ac8f6d));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x115f50c492de8ac5867ab3112630e70a8398552fcda4b89902a297643cfcfa5d), uint256(0x2c30b73bc5e557f3f99f9e097a17254b8f78c2f5b9f8b096dd23dfb693eebb83));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x18e72cadb65dc3bbfab72d3252fd45538dbff51a42e2f188a22cd5786eebb620), uint256(0x29d05fd7011f9e089a043e8b446709c3be18310dfaa4322508808cf102794d04));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x17088c4db63f58b4de84e148e1268e273f300b754d55ff09dc93d55605b19011), uint256(0x0dad8ac493ac5f8c05679ee314925f6a8cbb37fc8eea0c4a191dfb0d1f1f41c4));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x2128ecdec1a7edaf0b8138574bfc882b7020ec50edbfc1b13fe95c596c4efa1e), uint256(0x24aef48baa04a875486c9fab59ba1aa3f78ee398bb0d421e02b2051b9af2735e));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x088890eb5b78d824da268b091db26ff0abc358db3117e095d464b62b3bd1ee16), uint256(0x0df8ba0f3b79b038da858216be57c0cf447b7a1db9c660bbaf4639e92372233b));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x2a19f4aa5bf9f0f774d5f976168b82271b90ee5c24674119466963e2588c84df), uint256(0x289e6ab5500ccbd043e86e8e4da035dc8a65b97651bd4568ba16804b77eeb91f));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x05bcdbd9fa4b2703e36747e836b7ecac28fd034fedf7e19ce61c0e169677f2e9), uint256(0x0cd2ffed710bef881b7f53750b36fbefc5aeecf135ac7749e4d8bbd56289b7ba));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x1781302bc1e04a63919e64780086d68756044b1fa5b13e74d923bb3d624b8a63), uint256(0x0e6518c29c50caf8d77278975d7dba16f24942478a8acc48b5bdb872820e9d88));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x0bc75aac26769c0b33e213d6a0e2d7b4eb149bb71c887e2ebde3a63db5d024cd), uint256(0x02e01953ce735dce28a04b81802d28feafeadcbc20edcc9d81af91eddfb36ee2));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x04f398b22caeec328e6bbfaddc6087a84d1540f4e1ae5fb4ad552d61242f5dee), uint256(0x0808232ab1e077d413f13403e1241179999ca38787f712301d8d472ad1e76a9f));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x1cff0e94f483921e50c5f24c516be1f8bacf4f030ee00f72f7b361ab5c938baf), uint256(0x29a10e62c138c4b833f8411e8eb4cb271ceddc1e75746b207c5d38971f7ae0e1));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x03baa1dcd64ddc40903b176b15f3cbd7065f870a993816c1e8457a047a98c080), uint256(0x196ae498a44f93b2ecace82bf67b206b0f82420ce90c277ea658f4b40679d79d));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x26b236dace2d23917177adc69607f70f38f1df23f75e3cc63abdf2e7cf8af6d4), uint256(0x1acf42778c8a32fdc771f063b84ce75e89384287cc53e734f691821f87959bad));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x2156d637f6cc1715c383de7df165513fcc6c18b503a43fd1724fee2f80a3fb56), uint256(0x199ec9d91d493bb87be8f773476e74ebe4077d5ead8d9f89a3e28fac5a6bd4f9));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x2f5f19d3cb4ea6a9cb2764a14be0934d1ffa62c718ec93ca7cc4b84e93b20045), uint256(0x00ae68d11e33f865e40c188401148daf989c107a90892841a5f4e39da4341d32));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x172cb1bfcefa8ac53153ac698f57e09f76b496be938122926b92b0f8477260ce), uint256(0x2924d22c9edaa95f8d8fb8fafada8b20e4cb506ce245a8e5edf3278b9c1a9d30));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x1f75915ee244ba3524c837030795542d1cafa06c38027eef00b4399a4b11d286), uint256(0x0e44aae6d86a2c140151b5a7e103ad12ba08f5169d15c22fcf06d7f610a4ea62));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x26e158cefac4fd52858e807af90d9a595170fc11f551de0fc6fbc188fbc3e2a9), uint256(0x0b2948de1abd439ed5929867fd3bac9228b373f8c6b9d0cafe0111d6e0ed54e9));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x22048801b0ab233dcafbf0f6470824d66494a3d01d851fd6b8835097a4443f0c), uint256(0x1680e58207432e10b9a670b6324c08d0d8772d6a421f36feb31a6decf6e24afa));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x1bcd0b665223c60dd89035861704f70893bf11dc4d0181c644a1f5f03d6b06ff), uint256(0x152cdad993d707606844fc1139a1dd99010ddbe4fb7954f89d8e62cf8d92898c));
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
