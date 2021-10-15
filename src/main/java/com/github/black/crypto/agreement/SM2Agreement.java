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

package com.github.black.crypto.agreement;

import com.github.black.crypto.GMUtil;
import com.github.black.crypto.algorithm.ECCKeyPair;
import com.github.black.crypto.algorithm.ECPoint;
import com.github.black.crypto.algorithm.SM2;
import com.github.black.crypto.algorithm.SM2KeyPair;
import org.bouncycastle.util.Arrays;

import java.math.BigInteger;

/**
 * 中文 PDF3 密钥交换协议 http://www.gmbz.org.cn/main/viewfile/20180108023456003485.html
 */
public class SM2Agreement {

    private final SM2 sm2;

    public SM2Agreement(SM2 sm2) {
        this.sm2 = sm2;
    }

    /**
     * 协商秘钥交换.
     * 当对方的交换信息不包含 s 时,生成的协商信息对中会包含 s 以供对方校验.
     * 当对方的交换信息包含 s 时,会对其 s 进行校验.
     *
     * @param otherInfo 对方的公开信息
     * @param keyPair   用户秘钥对
     * @param r         用户随机秘钥对
     * @return 协商信息对
     */
    public AgreementPair generate(PublicInfo otherInfo, SM2KeyPair keyPair, ECCKeyPair r) throws KeyAgreementException {
        // A6_1,B5_1: 验证 Ro 是否满足椭圆曲线方程
        ECPoint Ro = otherInfo.getR();
        try {
            this.sm2.checkPoint(Ro);
        } catch (IllegalArgumentException e) {
            throw new KeyAgreementException("other's public key mismatch the curve");
        }
        // A2,B2: R = [r]G = (x2,y2)
        ECPoint R = r.getPublicKey();
        BigInteger n = this.sm2.getN();
        BigInteger the_2_w = BigInteger.valueOf(2).pow((int) Math.ceil(n.bitLength() / 2.0) - 1);
        // A4,B3: x_
        BigInteger x_ = the_2_w.subtract(BigInteger.ONE).and(R.getX()).add(the_2_w);
        // A5,B4: t = (d + x_ · r) mod n
        BigInteger t = x_.multiply(r.getPrivateKey()).add(keyPair.getPrivateKey()).mod(n);
        // A6_2,B5_2: xo_
        BigInteger xo_ = the_2_w.subtract(BigInteger.ONE).and(Ro.getX()).add(the_2_w);
        // A7,B6: u = [h · t](po + [xo_]Ro) = (xu,yu)
        ECPoint u = this.sm2.multiply(this.sm2.add(this.sm2.multiply(Ro, xo_), otherInfo.getP()), this.sm2.getH().multiply(t));
        if (u == ECPoint.INFINITY) {
            throw new KeyAgreementException("u is infinity");
        }
        byte[] xu = u.getX().toByteArray();
        byte[] yu = u.getY().toByteArray();
        byte[] so = otherInfo.getS();
        byte[] z = keyPair.getZ();
        // A8,B7: k = KDF(xu ∥ yu ∥ za ∥ zb, k)
        if (otherInfo.isInitiator()) {
            byte[] za = otherInfo.getZ();
            // 当请求方携带 s 时,进行校验
            if (so != null && !Arrays.constantTimeAreEqual(s2sa(xu, yu, za, z, Ro, R), so)) {
                throw new KeyAgreementException("initiator's tag mismatch");
            }
            // 生成 s
            return new AgreementPair(
                    this.s1sb(xu, yu, za, z, Ro, R),
                    this.sm2.kdf(otherInfo.getK(), xu, yu, za, z)
            );
        } else {
            byte[] zb = otherInfo.getZ();
            // 当响应方携带 s 时,进行校验
            if (so != null && !Arrays.constantTimeAreEqual(s1sb(xu, yu, z, zb, R, Ro), so)) {
                throw new KeyAgreementException("responder's tag mismatch");
            }
            // 生成 s
            return new AgreementPair(
                    this.s2sa(xu, yu, z, zb, R, Ro),
                    this.sm2.kdf(otherInfo.getK(), xu, yu, z, otherInfo.getZ())
            );
        }
    }

    private byte[] s1sb(byte[] xu, byte[] yu, byte[] za, byte[] zb, ECPoint Ra, ECPoint Rb) {
        return GMUtil.sm3(new byte[]{2}, yu,
                GMUtil.sm3(xu, za, zb,
                        Ra.getX().toByteArray(), Ra.getY().toByteArray(),
                        Rb.getX().toByteArray(), Rb.getY().toByteArray()
                ));
    }

    private byte[] s2sa(byte[] xu, byte[] yu, byte[] za, byte[] zb, ECPoint Ra, ECPoint Rb) {
        return GMUtil.sm3(new byte[]{3}, yu,
                GMUtil.sm3(xu, za, zb,
                        Ra.getX().toByteArray(), Ra.getY().toByteArray(),
                        Rb.getX().toByteArray(), Rb.getY().toByteArray()
                ));
    }

}
