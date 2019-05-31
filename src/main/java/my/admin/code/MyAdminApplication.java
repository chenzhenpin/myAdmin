package my.admin.code;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling//定时任务
@EnableAspectJAutoProxy
@EnableCaching
@MapperScan("my.manage.code.*.mapper")
public class MyAdminApplication {
    public static void main(String[] args) {
        SpringApplication.run(MyAdminApplication.class, args);
    }
}
