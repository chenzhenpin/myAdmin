package my.admin.code.sys.controller;

import my.admin.code.common.utils.ResData;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/sys/main")
public class SysMainController {
    @RequestMapping("/403")
    public ResData unauthorized(){
        return ResData.fail().setCode(403).setMsg("没有权限");
    }
}
