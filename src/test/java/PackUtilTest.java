import com.github.black.crypto.util.PackUtil;
import org.junit.Assert;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

public class PackUtilTest {

    @Test
    public void testBigEndianToInt() {
        byte[] bytes = "abcd".getBytes(StandardCharsets.UTF_8);
        int i = PackUtil.bigEndianToInt(bytes, 0);
        Assert.assertEquals(1633837924, i);
        Assert.assertEquals("61626364", Integer.toHexString(i));
    }

    @Test
    public void testIntToBigEndian() {
        byte[] bytes = new byte[4];
        PackUtil.intToBigEndian(1633837924, bytes, 0);
        Assert.assertEquals("abcd", new String(bytes));
    }
}
