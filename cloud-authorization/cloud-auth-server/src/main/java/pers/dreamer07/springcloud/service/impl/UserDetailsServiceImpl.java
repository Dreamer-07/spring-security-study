package pers.dreamer07.springcloud.service.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;
import pers.dreamer07.springcloud.constant.MessageConstant;

import javax.annotation.PostConstruct;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @program: cloud-authorization
 * @description: 校验和加载用户信息的业务类
 * @author: EMTKnight
 * @create: 2021-06-08
 **/
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private List<User> userList;

    @Autowired
    private PasswordEncoder passwordEncoder;

    /**
     * 作用在方法上，在当前 bean 实例创建且属性赋值完成后，调用该方法
     * 模拟加载数据库数据
     */
    @PostConstruct
    public void initData(){
        // 加密密码
        String encodePass = passwordEncoder.encode("123456");
        // 添加用户信息数据
        userList = new ArrayList<>(3);
        userList.add(new User("张三", encodePass, AuthorityUtils.commaSeparatedStringToAuthorityList("admin")));
        userList.add(new User("李四", encodePass, AuthorityUtils.commaSeparatedStringToAuthorityList("client")));
        userList.add(new User("王五", encodePass, AuthorityUtils.commaSeparatedStringToAuthorityList("client")));
    }

    /**
     * 加载用户信息
     * @param s
     * @return
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        // 获取指定的用户信息
        List<User> findUserList = userList.stream()
                .filter(user -> user.getUsername().equals(s))
                .collect(Collectors.toList());
        if (CollectionUtils.isEmpty(findUserList)){
            throw new UsernameNotFoundException(MessageConstant.USERNAME_PASSWORD_ERROR);
        }
        return findUserList.get(0);
    }
}
