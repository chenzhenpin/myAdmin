//package my.admin.code.sys.validator;
//
//import my.admin.code.sys.service.ISysUserService;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.stereotype.Component;
//import org.springframework.validation.Errors;
//
//@Component
//public class LoginValidator {
//    @Autowired
//    ISysUserService sysUserService;
//    public boolean supports(Class<?> clazz){
//        //注意User不能导错
//        return LoginForm.class.isAssignableFrom(clazz);
//    }
//    public void validate(Object target, Errors errors){
////		ValidationUtils.rejectIfEmpty(errors, "username", null,"用户名不能为空的");
////		ValidationUtils.rejectIfEmpty(errors, "password", null,"密码不能为空的");
//        LoginForm loginForm =(LoginForm)target;
//        ShiroUser shiroUser=null;
//        System.out.println(loginForm.getUsername());
//        shiroUser = shiroService.findFirstByUsername(loginForm.getUsername());
//        if(shiroUser==null){
//            errors.rejectValue("username", null, "该户名不存在");
//        }
//
//    }
//
//}
