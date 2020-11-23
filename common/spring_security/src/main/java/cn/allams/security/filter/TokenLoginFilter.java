package cn.allams.security.filter;

import cn.allams.security.entity.SecurityUser;
import cn.allams.security.entity.User;
import cn.allams.security.security.TokenManager;
import cn.allams.utils.utils.R;
import cn.allams.utils.utils.ResponseUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;

public class TokenLoginFilter extends UsernamePasswordAuthenticationFilter {

    private TokenManager tokenManager;
    private RedisTemplate redisTemplate;
    private AuthenticationManager authenticationManager;

    public TokenLoginFilter(AuthenticationManager authenticationManager, TokenManager tokenManager,
                            RedisTemplate redisTemplate) {
        this.tokenManager = tokenManager;
        this.redisTemplate = redisTemplate;
        this.authenticationManager = authenticationManager;
        this.setPostOnly(false);
        // 设置登陆路径和提交方式
        this.setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/admin/acl/login", "POST"));
    }

    /**
     * 获取表单提交用户名和密码
     * @param request
     * @param response
     * @return
     * @throws AuthenticationException
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {

        try {
            User user = new ObjectMapper().readValue(request.getInputStream(), User.class);
            return authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            user.getUsername(), user.getPassword(), new ArrayList<>()));
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException();
        }
    }

    /**
     * 认证成功调用方法
     * @param request
     * @param response
     * @param chain
     * @param authResult
     * @throws IOException
     * @throws ServletException
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            FilterChain chain, Authentication authResult)
            throws IOException, ServletException {
        // 认证成功，得到认证成功后用户信息
        SecurityUser user = (SecurityUser) authResult.getPrincipal();
        // 根据用户名生成token
        String token = tokenManager.createToken(user.getCurrentUserInfo().getUsername());
        // 把用户名称和权限列表放到redis
        redisTemplate.opsForValue().set(user.getCurrentUserInfo().getUsername(), user.getPermissionValueList());

        ResponseUtil.out(response, R.ok().data("token", token));
    }

    /**
     * 认证失败调用方法
     * @param request
     * @param response
     * @param failed
     * @throws IOException
     * @throws ServletException
     */
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        ResponseUtil.out(response, R.error());
    }
}
