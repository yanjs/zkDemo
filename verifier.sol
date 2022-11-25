// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
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

contract Verifier {
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
        vk.alpha = Pairing.G1Point(uint256(0x03a7022d7c81cde26087849376c8bc3452c5ba20958ebbb8fcc49d483daeead6), uint256(0x0a5b185fc1238fed18242b8ca7397163cc12aec53cd53b05584889d173b6c983));
        vk.beta = Pairing.G2Point([uint256(0x0ff1d80b961a10ea240e28b3bb80e1aa9ca3566e443ace6d6e014596821b2d4e), uint256(0x2b6b7eb28dc5944ff6cbab0b1db2010a98e06381124615dd06022d71d3387986)], [uint256(0x1d27de4a45f40a438d598cce985f3fe16dc2931571bd543548d307f6c9f1b4da), uint256(0x0c14ebcc134da44715a9266fc9b0961954323a34ad80ae5897e3983f6ed9602a)]);
        vk.gamma = Pairing.G2Point([uint256(0x2240527de0360d7882201910508a1efa64c188bad9e49e5d71b9d6c8c41d05d4), uint256(0x18a92cd631a3220efb4df537928ede140ef65ca1d719ecc8d1a8ef44d0283051)], [uint256(0x1181028b11f1b23135623ed54b7b5778fe705406c86fba7dec34b1cceb1f0c65), uint256(0x0e3aa9350e2ed01ed7f81f128f891d22e3870c8068fa7c0d41876e7bec90fed9)]);
        vk.delta = Pairing.G2Point([uint256(0x2cd8e6efd61fac05d4b6621fa78c2559e977e4d3978fbafbd61f832411572fe1), uint256(0x1f47d56a2908b8eb123afa9605d25cdd9a19346078713c1a875aaad355046fc5)], [uint256(0x242332de754074f8adf635ef054dff02ba91dbb8da041bfa804d5c1c4b1d3ef9), uint256(0x0a0e782542ab5a6872efcd78716d89692a0b0724f9a7b29c36829a909ce2c780)]);
        vk.gamma_abc = new Pairing.G1Point[](7);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x24411d68b67d0a1d38cb73ae87feedc839cc306f30c1619f4029b97a4b49352a), uint256(0x0d5baeed89cdf11bda2ce8a5eec70893aed40c07c143d36b40e03d781cdb22c2));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x07893d456f8d31064e411ac23a73c4ebe8d828a36e94d052c8f9aefafc965573), uint256(0x0e0edd95442a6673d4c1b49648ebbec9235ec74e6b424c4b03e1647f458f5eba));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x2ede71b8483d592a4c83731dc462d3207a7422c9544240e339f94fea55873ae1), uint256(0x1cf918cb61e8e942ea622833dec4698a4c58f94246b71c5ffe44305a7163a58e));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x2db60711738836bfabff03c1b8fdbe4a90dc7c9ad69560801021a54e528d02f1), uint256(0x0185f04308a6596369616bd763aa3742d12ad154ff047e184428ca25af6d8e87));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x2eb5c6e64a4615813dd179d34d799ba2ddce3f8211975f24e8a8371e6d492a0d), uint256(0x0cda6afe3e5493c4ebd33d3e5f901d027a751bd7cad7b932ca144efe65999294));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x0939d57e26d8cca2c38f32fad2df3bf9b6d694174dd43fe495c434cd4987f83e), uint256(0x17d47933fd8acbe115b9f1b6a5abffe8c6a12442a27c8149ddaa29bd0f8ef5c6));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x1fae0f4f122f6a43dee410124cf07d8b241b54fee903035c675efd393c2c64de), uint256(0x0950aa062b6a78fc2545dda43d62b33aec95d4229a584c2505e1864c25ea3398));
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
    event Verified(string s);
    function verifyTx(
            uint[2] memory a,
            uint[2] memory a_p,
            uint[2][2] memory b,
            uint[2] memory b_p,
            uint[2] memory c,
            uint[2] memory c_p,
            uint[2] memory h,
            uint[2] memory k,
            uint[7] memory input
        ) public returns (bool r) {
        Proof memory proof;
        proof.a = Pairing.G1Point(a[0], a[1]);
        // proof.a_p = Pairing.G1Point(a_p[0], a_p[1]);
        proof.b = Pairing.G2Point([b[0][0], b[0][1]], [b[1][0], b[1][1]]);
        // proof.b_p = Pairing.G1Point(b_p[0], b_p[1]);
        proof.c = Pairing.G1Point(c[0], c[1]);
        // proof.c_p = Pairing.G1Point(c_p[0], c_p[1]);
        // proof.h = Pairing.G1Point(h[0], h[1]);
        // proof.k = Pairing.G1Point(k[0], k[1]);
        uint[] memory inputValues = new uint[](input.length);
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            emit Verified("Transaction successfully verified.");
            return true;
        } else {
            return false;
        }
    }
}
