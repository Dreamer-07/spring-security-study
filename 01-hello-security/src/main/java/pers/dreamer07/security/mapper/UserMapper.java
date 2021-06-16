package pers.dreamer07.security.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import org.springframework.stereotype.Repository;
import pers.dreamer07.security.pojo.User;

/**
 * @program: spring-security
 * @description:
 * @author: EMTKnight
 * @create: 2021-03-21
 **/
@Repository
public interface UserMapper extends BaseMapper<User> {
}
