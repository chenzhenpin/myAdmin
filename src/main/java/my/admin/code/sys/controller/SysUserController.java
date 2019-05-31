package my.admin.code.sys.controller;


import my.admin.code.common.shiro.MD5toHash;
import my.admin.code.common.utils.ResData;
import my.admin.code.sys.entity.SysUser;
import my.admin.code.sys.form.RegisterForm;
import my.admin.code.sys.service.ISysUserService;
import my.admin.code.sys.validator.RegisterValidator;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.validation.Valid;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

/**
 * <p>
 * 用户表 前端控制器
 * </p>
 *
 * @author chen
 * @since 2019-05-31
 */
@RestController
@RequestMapping("/sys/user")
public class SysUserController {
    @Autowired
    ISysUserService sysUserService;
    @Autowired
    RegisterValidator registerValidator;

    @PostMapping("/register")
    public ResData register(@Valid RegisterForm registerForm, BindingResult result){
        registerValidator.validate(registerForm,result);
        if (result.hasErrors()){
            Map<String,Object> map = new HashMap<>();
            List<ObjectError>list= result.getAllErrors();
            for (ObjectError objectError: list){
                map.put(((FieldError)objectError).getField(),objectError.getDefaultMessage());
            }
            return  ResData.fail().setData(map);
        }
        String salt=registerForm.getUsername()+ new Random(1000).nextInt();
        String md5pwd=new MD5toHash(registerForm.getPassword(),salt).toMD5Hash();
        SysUser sysUser = new SysUser();
        sysUser.setAcctName(registerForm.getUsername());
        sysUser.setRealName(registerForm.getName());
        sysUser.setAcctPassword(md5pwd);
        sysUser.setSalt(salt);
        sysUserService.save(sysUser);
        return ResData.ok();
    }

    @PostMapping("/login")
    public ResData login(HttpServletRequest request) {//登录失败才会进入此方法
        String exceptionClassName = (String) request.getAttribute("shiroLoginFailure");
       if (UnknownAccountException.class.getName().equals(exceptionClassName)){
           return ResData.fail().setMsg("账号不存在").setCode(ResData.NO_LOGIN_CODE);
       }else if(IncorrectCredentialsException.class.getName().equals(exceptionClassName)) {
            return ResData.fail().setMsg("账号或密码错误").setCode(ResData.NO_LOGIN_CODE);
       }
       return ResData.fail().setCode(ResData.NO_LOGIN_CODE);
    }
    @RequestMapping("/success")
    public ResData success() {//登录成功会进入此方法
       return ResData.ok().setMsg("登录成功");
    }
    @RequestMapping("/logout")
    public ResData logout(HttpSession session){
        //session失效
        session.invalidate();
        return ResData.ok().setMsg("退出成功");
    }
}
