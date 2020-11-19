package cn.allams.security.security;

import cn.allams.utils.utils.MD5;
import org.springframework.security.crypto.password.PasswordEncoder;

public class DefalutPasswordDecoder implements PasswordEncoder {
    public DefalutPasswordDecoder() {
        this(-1);
    }

    public DefalutPasswordDecoder(int strength) {

    }
    /**
     * 进行MD5加密
     * @param charSequence 要加密的串
     * @return 加密后的字符串
     */
    @Override
    public String encode(CharSequence charSequence) {
        return MD5.encrypt(charSequence.toString());
    }

    /**
     * 进行密码比对
     * @param charSequence
     * @param s
     * @return
     */
    @Override
    public boolean matches(CharSequence charSequence, String s) {
        return s.equals(MD5.encrypt(charSequence.toString()));
    }
}
