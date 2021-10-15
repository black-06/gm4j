/*
 * Copyright 2021 hello.bug@foxmail.com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.github.black.crypto.algorithm;

import com.github.black.crypto.signer.ECCSigner;
import com.github.black.crypto.signer.Signature;
import org.junit.Assert;
import org.junit.Test;

import java.math.BigInteger;

public class ECCTest {

    /**
     * SECP256K1 比特币曲线
     */
    private static final ECC SECP256K1 = new ECC(
            new BigInteger("0"),
            new BigInteger("7"),
            new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16),
            new BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16),
            new BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16),
            new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16),
            new BigInteger("1")
    );

    @Test
    public void testECDHE() {
        // a 的秘钥对
        ECCKeyPair a = SECP256K1.generateKeyPair();
        // b 的秘钥对
        ECCKeyPair b = SECP256K1.generateKeyPair();
        // 共享秘钥 S
        ECPoint sA = SECP256K1.multiply(b.getPublicKey(), a.getPrivateKey());
        ECPoint sB = SECP256K1.multiply(a.getPublicKey(), b.getPrivateKey());
        Assert.assertEquals(sA, sB);
    }

    @Test
    public void testSignature() {
        ECCSigner signer = new ECCSigner(SECP256K1);
        // 消息
        String msg = "Hello!";
        // 秘钥对
        ECCKeyPair p = SECP256K1.generateKeyPair();
        // 签名
        Signature s = signer.sign(p.getPrivateKey(), msg);
        // 验证签名
        Assert.assertTrue(signer.verify(p.getPublicKey(), s, msg));
        Assert.assertFalse(signer.verify(p.getPublicKey(), s, "Hi there!"));
    }
}
