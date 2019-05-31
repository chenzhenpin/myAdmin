package my.admin.code.sys.validator;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import my.admin.code.sys.entity.SysUser;
import my.admin.code.sys.form.RegisterForm;
import my.admin.code.sys.service.ISysUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;


@Component
public class RegisterValidator implements Validator {
	@Autowired
	ISysUserService sysUserService;
	public boolean supports(Class<?> clazz){
		return RegisterForm.class.isAssignableFrom(clazz);
	}
	public void validate(Object target, Errors errors){
//		ValidationUtils.rejectIfEmpty(errors, "username", null,"用户名不能为空的");
//		ValidationUtils.rejectIfEmpty(errors, "password", null,"密码不能为空的");
		RegisterForm registerForm =(RegisterForm)target;
		QueryWrapper<SysUser> queryWrapper= new QueryWrapper<>();
		queryWrapper.eq("acct_name",registerForm.getUsername());
		SysUser sysUser = sysUserService.getOne(queryWrapper);
		if(sysUser!=null){
			errors.rejectValue("username", null, "用户名已存在");
		}
	}

}
