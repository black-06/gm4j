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

package com.github.black.crypto.signer;

import com.github.black.crypto.algorithm.ECPoint;
import com.github.black.crypto.algorithm.SM2;
import com.github.black.crypto.algorithm.SM2KeyPair;
import org.junit.Assert;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

public class SM2SignerTest {

    private static final byte[] ID_A = "ALICE123@YAHOO.COM".getBytes(StandardCharsets.US_ASCII);

    @Test
    public void testSignature() {
        SM2Signer signer = new SM2Signer(SM2.SPEC);
        // 消息
        byte[] msg = "Hello!".getBytes(StandardCharsets.UTF_8);
        // 秘钥对
        SM2KeyPair skp = SM2.SPEC.generateKeyPair(ID_A);
        // 公钥
        ECPoint p = skp.getPublicKey();
        // 用户信息
        byte[] z = skp.getZ();
        // 签名
        Signature s = signer.sign(skp, msg);
        // 验证签名
        Assert.assertTrue(signer.verify(p, z, s, msg));
        Assert.assertFalse(signer.verify(p, z, s, "Hi there!".getBytes(StandardCharsets.UTF_8)));
        // 错误用户
        byte[] ez = SM2.SPEC.generateZ("other".getBytes(StandardCharsets.UTF_8), p);
        Assert.assertFalse(signer.verify(p, ez, s, msg));
    }
}
