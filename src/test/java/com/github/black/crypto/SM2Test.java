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

package com.github.black.crypto;

import com.github.black.crypto.digests.SM2;
import com.github.black.crypto.digests.SM3;
import com.github.black.crypto.pojo.KeyPair;
import com.github.black.crypto.pojo.Signature;
import com.github.black.crypto.util.Hex;
import com.github.black.crypto.util.PackUtil;
import com.github.black.ec.ECOverPF;
import com.github.black.ec.ECPoint;
import org.junit.Assert;
import org.junit.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

public class SM2Test {

    private static final ECOverPF CURVE = new ECOverPF(
            // a
            new BigInteger("787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498", 16),
            // b
            new BigInteger("63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A", 16),
            // p
            new BigInteger("8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3", 16),
            // gx
            new BigInteger("421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D", 16),
            // gy
            new BigInteger("0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2", 16),
            // n
            new BigInteger("8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7", 16),
            // h
            new BigInteger("1", 16)
    );

    private static final byte[] ID_A = "ALICE123@YAHOO.COM".getBytes(StandardCharsets.US_ASCII);

    private static final byte[] ID_B = "BILL456@YAHOO.COM".getBytes(StandardCharsets.US_ASCII);

    private byte[] getEntl(byte[] id) {
        int len = id.length * 8;
        byte[] entl = new byte[2];
        entl[0] = (byte) (len >> 8 & 255);
        entl[1] = (byte) (len & 255);
        return entl;
    }

    private void assertHexEquals(String hex, byte[] bytes) {
        Assert.assertEquals(hex.toUpperCase(Locale.ROOT), Hex.encodeHex(bytes).toUpperCase(Locale.ROOT));
    }

    /**
     * http://www.gmbz.org.cn/main/viewfile/20180108023346264349.html
     * <p>
     * A.1
     */
    @Test
    public void part2_A1() {
        assertHexEquals("414C494345313233405941484F4F2E434F4D", ID_A);
        assertHexEquals("0090", getEntl(ID_A));
    }

    /**
     * http://www.gmbz.org.cn/main/viewfile/20180108023346264349.html
     * <p>
     * A.2
     */
    @Test
    public void part2_A2() {
        // 待签名消息 m
        byte[] m = "message digest".getBytes(StandardCharsets.US_ASCII);
        assertHexEquals("6D65737361676520646967657374", m);
        // 私钥 d
        BigInteger d = new BigInteger("128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263", 16);
        // 公钥 p
        ECPoint pa = CURVE.multiplyG(d);
        assertHexEquals("0AE4C7798AA0F119471BEE11825BE46202BB79E2A5844495E97C04FF4DF2548A", pa.getX().toByteArray());
        assertHexEquals("7C0240F88F1CD4E16352A73C17B7F16F07353E53A176D684A9FE0C6BB798E857", pa.getY().toByteArray());
        CURVE.checkPoint(pa);
        // Z
        SM3 sm3 = new SM3();
        sm3.update(getEntl(ID_A));
        byte[] z = GMUtil.sm3(
                getEntl(ID_A), ID_A,
                CURVE.getA().toByteArray(),
                CURVE.getB().toByteArray(),
                CURVE.getG().getX().toByteArray(),
                CURVE.getG().getY().toByteArray(),
                pa.getX().toByteArray(),
                pa.getY().toByteArray()
        );
        assertHexEquals("F4A38489E32B45B6F876E3AC2168CA392362DC8F23459C1D1146FC3DBFB7BC9A", z);
        // e
        SM3 sm3e = new SM3();
        sm3e.update(z);
        sm3e.update(m);
        byte[] e = sm3e.digest();
        assertHexEquals("B524F552CD82B8B028476E005C377FB19A87E6FC682D48BB5D42E3D9B9EFFE76", e);
        BigInteger ei = new BigInteger(1, e);
        // random k
        BigInteger k = new BigInteger("6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F", 16);
        // 椭圆曲线点 (x1,y1)
        ECPoint p = CURVE.multiplyG(k);
        assertHexEquals("110FCDA57615705D5E7B9324AC4B856D23E6D9188B2AE47759514657CE25D112", p.getX().toByteArray());
        assertHexEquals("1C65D68A4A08601DF24B431E0CAB4EBE084772B3817E85811A8510B2DF7ECA1A", p.getY().toByteArray());
        // 签名 r
        BigInteger r = (ei.add(p.getX()).mod(CURVE.getN()));
        assertHexEquals("40F1EC59F793D9F49E09DCEF49130D4194F79FB1EED2CAA55BACDB49C4E755D1", r.toByteArray());
        // 签名 s
        BigInteger s = d.add(BigInteger.ONE).modInverse(CURVE.getN()).multiply(k.subtract(r.multiply(d))).mod(CURVE.getN());
        assertHexEquals("6FC6DAC32C5D5CF10C77DFB20F7C2EB667A457872FB09EC56327A67EC7DEEBE7", s.toByteArray());
        // 验证签名
        assertHexEquals("B524F552CD82B8B028476E005C377FB19A87E6FC682D48BB5D42E3D9B9EFFE76", e);
        BigInteger t = r.add(s).mod(CURVE.getN());
        assertHexEquals("2B75F07ED7ECE7CCC1C8986B991F441AD324D6D619FE06DD63ED32E0C997C801", t.toByteArray());
        // 椭圆曲线点 (x0',y0')
        p = CURVE.multiplyG(s);
        assertHexEquals("7DEACE5FD121BC385A3C6317249F413D28C17291A60DFD83B835A45392D22B0A", p.getX().toByteArray());
        assertHexEquals("2E49D5E5279E5FA91E71FD8F693A64A3C4A9461115A4FC9D79F34EDC8BDDEBD0", p.getY().toByteArray());
        // 椭圆曲线点 (x00',y00')
        p = CURVE.multiply(pa, t);
        assertHexEquals("1657FA75BF2ADCDC3C1F6CF05AB7B45E04D3ACBE8E4085CFA669CB2564F17A9F", p.getX().toByteArray());
        assertHexEquals("19F0115F21E16D2F5C3A485F8575A128BBCDDF80296A62F6AC2EB842DD058E50", p.getY().toByteArray());
        // 椭圆曲线点 (x1',y1')
        p = CURVE.add(CURVE.multiplyG(s), p);
        assertHexEquals("110FCDA57615705D5E7B9324AC4B856D23E6D9188B2AE47759514657CE25D112", p.getX().toByteArray());
        assertHexEquals("1C65D68A4A08601DF24B431E0CAB4EBE084772B3817E85811A8510B2DF7ECA1A", p.getY().toByteArray());
        BigInteger R = ei.add(p.getX()).mod(CURVE.getN());
        Assert.assertEquals(r, R);
    }

    /**
     * http://www.gmbz.org.cn/main/viewfile/20180108023456003485.html
     * <p>
     * A.2.SM2 秘钥交换
     */
    @Test
    public void part3_A2() {
        BigInteger n = CURVE.getN();
        // 2 ^ w
        BigInteger w = BigInteger.valueOf(2).pow((int) Math.ceil(n.bitLength() / 2.0) - 1);
        // 私钥 da
        BigInteger da = new BigInteger("6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE", 16);
        // 公钥 pa
        ECPoint pa = CURVE.multiplyG(da);
        assertHexEquals("3099093BF3C137D8FCBBCDF4A2AE50F3B0F216C3122D79425FE03A45DBFE1655", pa.getX().toByteArray());
        assertHexEquals("3DF79E8DAC1CF0ECBAA2F2B49D51A4B387F2EFAF482339086A27A8E05BAED98B", pa.getY().toByteArray());
        CURVE.checkPoint(pa);
        // 私钥 db
        BigInteger db = new BigInteger("5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53", 16);
        // 公钥 pb
        ECPoint pb = CURVE.multiplyG(db);
        assertHexEquals("245493D446C38D8CC0F118374690E7DF633A8A4BFB3329B5ECE604B2B4F37F43", pb.getX().toByteArray());
        assertHexEquals("53C0869F4B9E17773DE68FEC45E14904E0DEA45BF6CECF9918C85EA047C60A4C", pb.getY().toByteArray());
        CURVE.checkPoint(pb);
        // 杂凑值 za
        byte[] za = GMUtil.sm3(
                getEntl(ID_A), ID_A,
                CURVE.getA().toByteArray(), CURVE.getB().toByteArray(),
                CURVE.getG().getX().toByteArray(), CURVE.getG().getY().toByteArray(),
                pa.getX().toByteArray(), pa.getY().toByteArray()
        );
        assertHexEquals("E4D1D0C3CA4C7F11BC8FF8CB3F4C02A78F108FA098E51A668487240F75E20F31", za);
        // 杂凑值 zb
        byte[] zb = GMUtil.sm3(
                getEntl(ID_B), ID_B,
                CURVE.getA().toByteArray(), CURVE.getB().toByteArray(),
                CURVE.getG().getX().toByteArray(), CURVE.getG().getY().toByteArray(),
                pb.getX().toByteArray(), pb.getY().toByteArray()
        );
        assertHexEquals("6B4B6D0E276691BD4A11BF72F4FB501AE309FDACB72FA6CC336E6656119ABD67", zb);
        // 随机数 ra
        BigInteger ra = new BigInteger("83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563", 16);
        ECPoint Ra = CURVE.multiplyG(ra);
        assertHexEquals("6CB5633816F4DD560B1DEC458310CBCC6856C09505324A6D23150C408F162BF0", Ra.getX().toByteArray());
        assertHexEquals("0D6FCF62F1036C0A1B6DACCF57399223A65F7D7BF2D9637E5BBBEB857961BF1A", Ra.getY().toByteArray());
        /*========================================= B1-B10 =========================================*/
        // 随机数 rb
        BigInteger rb = new BigInteger("33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80", 16);
        ECPoint Rb = CURVE.multiplyG(rb);
        assertHexEquals("1799B2A2C778295300D9A2325C686129B8F2B5337B3DCF4514E8BBC19D900EE5", Rb.getX().toByteArray());
        assertHexEquals("54C9288C82733EFDF7808AE7F27D0E732F7C73A7D9AC98B7D8740A91D0DB3CF4", Rb.getY().toByteArray());

        BigInteger x2_ = Rb.getX().and(w.subtract(BigInteger.ONE)).add(w);
        assertHexEquals("00B8F2B5337B3DCF4514E8BBC19D900EE5", x2_.toByteArray());
        // tb
        BigInteger tb = x2_.multiply(rb).add(db).mod(n);
        assertHexEquals("2B2E11CBF03641FC3D939262FC0B652A70ACAA25B5369AD38B375C0265490C9F", tb.toByteArray());

        BigInteger x1_ = Ra.getX().and(w.subtract(BigInteger.ONE)).add(w);
        assertHexEquals("00E856C09505324A6D23150C408F162BF0", x1_.toByteArray());
        // 椭圆曲线点 RA (xA0,yA0)
        ECPoint p = CURVE.multiply(Ra, x1_);
        BigInteger xa0 = p.getX();
        assertHexEquals("2079015F1A2A3C132B67CA9075BB28031D6F22398DD8331E72529555204B495B", xa0.toByteArray());
        BigInteger ya0 = p.getY();
        assertHexEquals("6B3FE6FB0F5D5664DCA16128B5E7FCFDAFA5456C1E5A914D1300DB61F37888ED", ya0.toByteArray());
        // 椭圆曲线点 (xA1,yA1)
        p = CURVE.add(pa, p);
        BigInteger xa1 = p.getX();
        assertHexEquals("1C006A3BFF97C651B7F70D0DE0FC09D23AA2BE7A8E9FF7DAF32673B416349B92", xa1.toByteArray());
        BigInteger ya1 = p.getY();
        assertHexEquals("5DC74F8ACC114FC6F1A75CB286864F347F9B2CF29326A27079B7D37AFC1C145B", ya1.toByteArray());
        // 椭圆曲线点 V (xv,yv)
        ECPoint v = CURVE.multiply(p, CURVE.getH().multiply(tb));
        byte[] xv = v.getX().toByteArray();
        assertHexEquals("47C826534DC2F6F1FBF28728DD658F21E174F48179ACEF2900F8B7F566E40905", xv);
        byte[] yv = v.getY().toByteArray();
        assertHexEquals("2AF86EFE732CF12AD0E09A1F2556CC650D9CCCE3E249866BBB5C6846A4C4A295", yv);
        // kb
        byte[] kb = kdf(16, xv, yv, za, zb);
        assertHexEquals("55B0AC62A6B927BA23703832C853DED4", kb);
        // s2 = Hash(0x03 ∥ yV ∥ Hash(xV ∥ ZA ∥ ZB ∥ x1 ∥ y1 ∥ x2 ∥ y2))
        byte[] s2 = GMUtil.sm3(new byte[]{3}, yv,
                GMUtil.sm3(xv, za, zb,
                        Ra.getX().toByteArray(), Ra.getY().toByteArray(),
                        Rb.getX().toByteArray(), Rb.getY().toByteArray()
                ));
        // sb = Hash(0x02 ∥ yV ∥ Hash(xV ∥ ZA ∥ ZB ∥ x1 ∥ y1 ∥ x2 ∥ y2))
        byte[] sb = GMUtil.sm3(new byte[]{2}, yv,
                GMUtil.sm3(xv, za, zb,
                        Ra.getX().toByteArray(), Ra.getY().toByteArray(),
                        Rb.getX().toByteArray(), Rb.getY().toByteArray()
                ));
        assertHexEquals("284C8F198F141B502E81250F1581C7E9EEB4CA6990F9E02DF388B45471F5BC5C", sb);
        /*========================================= A4-A10 =========================================*/
        // ta
        BigInteger ta = x1_.multiply(ra).add(da).mod(n);
        assertHexEquals("236CF0C7A177C65C7D55E12D361F7A6C174A78698AC099C0874AD0658A4743DC", ta.toByteArray());
        // 椭圆曲线点 RB (xB0,yB0)
        p = CURVE.multiply(Rb, x2_);
        BigInteger xb0 = p.getX();
        assertHexEquals("668642746BFC066A1E731ECFFF51131BDC81CF609701CB8C657B25BF55B7015D", xb0.toByteArray());
        BigInteger yb0 = p.getY();
        assertHexEquals("1988A7C681CE1B509AC69F49D72AE60E8B71DB6CE087AF8499FEEF4CCD523064", yb0.toByteArray());
        // 椭圆曲线点 (xB1,yB1)
        p = CURVE.add(pb, p);
        BigInteger xb1 = p.getX();
        assertHexEquals("7D2B443510886AD7CA3911CF2019EC07078AFF116E0FC409A9F75A3901F306CD", xb1.toByteArray());
        BigInteger yb1 = p.getY();
        assertHexEquals("331F0C6C0FE08D405FFEDB307BC255D68198653BDCA68B9CBA100E73197E5D24", yb1.toByteArray());
        // U
        ECPoint u = CURVE.multiply(p, CURVE.getH().multiply(ta));
        byte[] xu = u.getX().toByteArray();
        assertHexEquals("47C826534DC2F6F1FBF28728DD658F21E174F48179ACEF2900F8B7F566E40905", xu);
        byte[] yu = u.getY().toByteArray();
        assertHexEquals("2AF86EFE732CF12AD0E09A1F2556CC650D9CCCE3E249866BBB5C6846A4C4A295", yu);
        // ka
        byte[] ka = kdf(16, xu, yu, za, zb);
        assertHexEquals("55B0AC62A6B927BA23703832C853DED4", ka);
        // s1 = Hash(0x02 ∥ yU ∥ Hash(xU ∥ ZA ∥ ZB ∥ x1 ∥ y1 ∥ x2 ∥ y2))
        byte[] s1 = GMUtil.sm3(new byte[]{2}, yu,
                GMUtil.sm3(xu, za, zb,
                        Ra.getX().toByteArray(), Ra.getY().toByteArray(),
                        Rb.getX().toByteArray(), Rb.getY().toByteArray()
                ));
        // sa = Hash(0x03 ∥ yU ∥ Hash(xU ∥ ZA ∥ ZB ∥ x1 ∥ y1 ∥ x2 ∥ y2))
        byte[] sa = GMUtil.sm3(new byte[]{3}, yu,
                GMUtil.sm3(xu, za, zb,
                        Ra.getX().toByteArray(), Ra.getY().toByteArray(),
                        Rb.getX().toByteArray(), Rb.getY().toByteArray()
                ));
        assertHexEquals("23444DAF8ED7534366CB901C84B3BDBB63504F4065C1116C91A4C00697E6CF7A", sa);

        /*========================================= check =========================================*/
        Assert.assertEquals(Hex.encodeHex(s1), Hex.encodeHex(sb));
        Assert.assertEquals(Hex.encodeHex(s2), Hex.encodeHex(sa));
    }

    private byte[] kdf(int k, byte[]... zs) {
        byte[] rst = new byte[k];
        SM3 sm3 = new SM3();
        int ct = 0, offset = 0;
        byte[] buff = new byte[4];
        while (offset < k) {
            sm3.reset();
            for (byte[] z : zs) {
                sm3.update(z);
            }
            PackUtil.intToBigEndian(++ct, buff, 0);
            sm3.update(buff);
            int len = Math.min(32, k - offset);
            System.arraycopy(sm3.digest(), 0, rst, offset, len);
            offset += len;
        }
        return rst;
    }

    @Test
    public void testSignature() {
        SM2 sm2 = new SM2();
        // 消息
        byte[] msg = "Hello!".getBytes(StandardCharsets.UTF_8);
        // 秘钥对
        KeyPair p = sm2.generateKeyPair();
        // 签名
        Signature s = sm2.sign(p, ID_A, msg);
        // 验证签名
        Assert.assertTrue(sm2.verify(p.getPublicKey(), s, ID_A, msg));
        Assert.assertFalse(sm2.verify(p.getPublicKey(), s, ID_A, "Hi there!".getBytes(StandardCharsets.UTF_8)));
        Assert.assertFalse(sm2.verify(p.getPublicKey(), s, "other".getBytes(StandardCharsets.UTF_8), msg));
    }
}
