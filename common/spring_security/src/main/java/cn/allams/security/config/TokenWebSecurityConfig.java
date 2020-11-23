package cn.allams.security.config;

import cn.allams.security.filter.TokenLoginFilter;
import cn.allams.security.security.DefalutPasswordEncoder;
import cn.allams.security.security.TokenLogoutHandler;
import cn.allams.security.security.TokenManager;
import cn.allams.security.security.UnauthEntryPoint;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class TokenWebSecurityConfig extends WebSecurityConfigurerAdapter {

    private TokenManager tokenManager;
    private RedisTemplate redisTemplate;
    private DefalutPasswordEncoder defalutPasswordEncoder;
    private UserDetailsService userDetailsService;

    @Autowired
    public TokenWebSecurityConfig(UserDetailsService userDetailsService, DefalutPasswordEncoder defalutPasswordEncoder,
                                  TokenManager tokenManager, RedisTemplate redisTemplate) {
        this.defalutPasswordEncoder = defalutPasswordEncoder;
        this.redisTemplate = redisTemplate;
        this.userDetailsService = userDetailsService;
        this.tokenManager = tokenManager;
    }

    /**
     * 配置设置
     */
//设置退出的地址和token，redis 操作地址
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.exceptionHandling()
                .authenticationEntryPoint(new UnauthEntryPoint()) //没有权限当问
                .and().csrf().disable()
                .authorizeRequests()
                .anyRequest().authenticated()
                .and().logout().logoutUrl("/admin/acl/index/logout")//退出的路径
                .addLogoutHandler(new
                        TokenLogoutHandler(tokenManager,redisTemplate)).and()
                .addFilter(new TokenLoginFilter(authenticationManager(),
                        tokenManager, redisTemplate))
                .addFilter(new TokenLoginFilter(authenticationManager(), tokenManager,
                        redisTemplate)).httpBasic();
    }

    /**
     * 密码处理
     */
    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception
    {
        auth.userDetailsService(userDetailsService).passwordEncoder(defalutPasswordEncoder);
    }
    /**
     * 配置哪些请求不拦截
     */
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/api/**" , "/swagger-ui.html/**");
    }




}
