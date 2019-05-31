package my.admin.code.common.utils;

import com.alibaba.fastjson.JSON;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.DigestUtils;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class CommonUtils {

    public static String passwordMD5(String password){
        return DigestUtils.md5DigestAsHex((password+"1a2b3c4d").getBytes());
    }
    public static void writeJson(HttpServletResponse response, ResData error) {
        try {
            response.setContentType("text/json;charset=UTF-8");
            response.getWriter().write(JSON.toJSONString(error));
        } catch (IOException e) {
            Logger log = LoggerFactory.getLogger(CommonUtils.class);
            log.error("---writeJson:"+e.getMessage());
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        System.out.println(passwordMD5("1"));
    }
}
