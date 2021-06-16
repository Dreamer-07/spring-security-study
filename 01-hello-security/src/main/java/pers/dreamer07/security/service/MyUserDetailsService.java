package pers.dreamer07.security.service;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import pers.dreamer07.security.mapper.UserMapper;
import pers.dreamer07.security.pojo.User;

import java.util.List;

/**
 * @program: spring-security
 * @description:
 * @author: EMTKnight
 * @create: 2021-03-16
 **/
@Service("userDetailsService")
public class MyUserDetailsService implements UserDetailsService {

    @Autowired
    @Qualifier("passwordEncoder")
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UserMapper userMapper;

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        /*
        * 配置对应的权限、角色列表
        *   - 配置用户角色时需要在前面加上 'ROLE_'
        * */
        List<GrantedAuthority> grantedAuthorities = AuthorityUtils.commaSeparatedStringToAuthorityList("master");
        QueryWrapper<User> wrapper = new QueryWrapper<>();
        wrapper.eq("username", s);
        User user = userMapper.selectOne(wrapper);
//        return new User("geek", passwordEncoder.encode("123456"), grantedAuthorities);
        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                passwordEncoder.encode(user.getPassword()),
                grantedAuthorities
        );
    }

}
