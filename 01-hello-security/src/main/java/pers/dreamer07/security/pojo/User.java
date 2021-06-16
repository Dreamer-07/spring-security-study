package pers.dreamer07.security.pojo;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

/**
 * @program: spring-security
 * @description:
 * @author: EMTKnight
 * @create: 2021-03-21
 **/
@Data
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class User {

    private Integer id;

    private String username;

    private String password;

}
