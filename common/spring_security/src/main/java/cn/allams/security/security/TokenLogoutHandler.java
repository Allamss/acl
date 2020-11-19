package cn.allams.security.security;

import cn.allams.utils.utils.R;
import cn.allams.utils.utils.ResponseUtil;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 退出处理器
 * @author Some1Ls
 */
public class TokenLogoutHandler implements LogoutHandler {

    private TokenManager tokenManager;
    private RedisTemplate redisTemplate;

    public TokenLogoutHandler(TokenManager tokenManager, RedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
        this.tokenManager = tokenManager;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        //从header里面获取token
        String token = request.getHeader("token");
        if (token != null) {
            //服务器移除token（服务器就没存，装装样子罢了）
            tokenManager.removeToken(token);
            //Redis中移除
            String username = tokenManager.getUserInfoFromToken(token);
            redisTemplate.delete(username);
        }
        ResponseUtil.out(response, R.ok());
    }
}
