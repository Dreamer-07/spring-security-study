package pers.dreamer07.springcloud.service.impl;

import com.google.common.collect.ImmutableList;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import pers.dreamer07.springcloud.constant.RedisConstant;

import javax.annotation.PostConstruct;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * @program: cloud-authorization
 * @description: 资源与角色匹配关系管理的业务类
 * @author: EMTKnight
 * @create: 2021-06-10
 **/
@Service
public class ResourceServerImpl {

    @Autowired
    private RedisTemplate<String, Object> redisTemplate;


    /**
     * 将资源与对应的角色匹配关系保存到 redis 中
     */
    @PostConstruct
    public void initData() {
        Map<String, List<String>> resourceRolesMap = new TreeMap<>();
        resourceRolesMap.put("/services/**", ImmutableList.of("client"));
        resourceRolesMap.put("/api/**", ImmutableList.of("admin"));
        redisTemplate.opsForHash().putAll(RedisConstant.RESOURCE_ROLES_MAP, resourceRolesMap);
    }

}
