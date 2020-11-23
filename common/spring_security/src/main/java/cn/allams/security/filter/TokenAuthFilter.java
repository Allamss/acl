package cn.allams.security.filter;

import cn.allams.security.security.TokenManager;
import org.omg.IOP.ServiceContextHolder;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class TokenAuthFilter extends BasicAuthenticationFilter {

    private TokenManager tokenManager;
    private RedisTemplate redisTemplate;

    public TokenAuthFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
        this.redisTemplate = redisTemplate;
        this.tokenManager = tokenManager;
    }

    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
        //从header中获取token
        String token = request.getHeader("token");
        if (token != null) {
            //从token中获取用户名
            String username = tokenManager.getUserInfoFromToken(token);

            //从redis获取对应权限列表
            List<String> permissions = (List<String>) redisTemplate.opsForValue().get(username);
            //把字符串权限列表转成 GrantedAuthority 类型权限列表
            Collection<GrantedAuthority> authorities = new ArrayList<>();
            for (String permission : permissions) {
                SimpleGrantedAuthority auth = new SimpleGrantedAuthority(permission);
                authorities.add(auth);
            }

            return new UsernamePasswordAuthenticationToken(username, token, authorities);
        }
        return null;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        //获取当前认证成功用户权限信息
        UsernamePasswordAuthenticationToken authRequest = null;
        //判断如果有权限信息，放到权限上下文中
        if (authRequest != null) {
            SecurityContextHolder.getContext().setAuthentication(authRequest);
        }
    }
}
