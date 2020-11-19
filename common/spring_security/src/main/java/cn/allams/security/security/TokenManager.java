package cn.allams.security.security;

import io.jsonwebtoken.CompressionCodecs;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Component;

import java.util.Date;

/**
 * token管理
 * @author Some1Ls
 */
@Component
public class TokenManager {

    /**
     * token有效时长
     */
    private long TOKEN_ECPRIATION = 24 * 60 * 60 * 1000;

    /**
     * 编码密钥
     */
    private String TOKEN_SIGN_KEY = "123456";

    /**
     * 根据用户名生成token
     * @param username 用户名
     * @return
     */
    public String createToken(String username) {
        String token = Jwts.builder().setSubject(username)
                .setExpiration(new Date(System.currentTimeMillis() + TOKEN_ECPRIATION))
                .signWith(SignatureAlgorithm.HS512, TOKEN_SIGN_KEY).compressWith(CompressionCodecs.GZIP).compact();
        return token;
    }

    /**
     * 根据token字符串得到用户信息
     * @param token token
     * @return
     */
    public String getUserInfoFromToken(String token) {
        String userinfo = Jwts.parser().setSigningKey(TOKEN_SIGN_KEY).parseClaimsJws(token).getBody().getSubject();
        return userinfo;
    }

    /**
     * 删除token
     * @param token token
     */
    public void removeToken(String token) { }

}
