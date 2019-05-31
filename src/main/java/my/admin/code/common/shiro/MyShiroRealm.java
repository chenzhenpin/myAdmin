package my.admin.code.common.shiro;//package my.admin.code.shiro;


import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import my.admin.code.sys.entity.SysMenu;
import my.admin.code.sys.entity.SysRole;
import my.admin.code.sys.entity.SysUser;
import my.admin.code.sys.service.ISysMenuService;
import my.admin.code.sys.service.ISysRoleService;
import my.admin.code.sys.service.ISysUserService;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
public class MyShiroRealm extends AuthorizingRealm {
    //用于用户查询
    @Autowired
    ISysUserService  sysUserService;
    @Autowired
    ISysRoleService sysRoleService;
    @Autowired
    ISysMenuService sysMenuService;

    //角色权限和对应权限添加
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        System.out.println("权限配置-->MyShiroRealm.doGetAuthorizationInfo()");
        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
        SysUser sysUser  = (SysUser)principals.getPrimaryPrincipal();
        List<SysRole>sysRoles=sysRoleService.getRolesByUserId(sysUser.getId());
        for(SysRole role:sysRoles){
            authorizationInfo.addRole(role.getRoleCode());
            List<SysMenu>sysMenus=sysMenuService.getMenusByRoleId(role.getId());
            for(SysMenu sysMenu :sysMenus){
                authorizationInfo.addStringPermission(sysMenu.getResourceCode());
            }
        }
        return authorizationInfo;
    }


    //用户认证
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token)
            throws AuthenticationException {
        System.out.println("MyShiroRealm.doGetAuthenticationInfo()");
        //获取用户的输入的账号.
        String username = (String) token.getPrincipal();
        SysUser sysUser=null;
        //通过username从数据库中查找 User对象，如果找到，没找到.
        //实际项目中，这里可以根据实际情况做缓存，如果不做，Shiro自己也是有时间间隔机制，2分钟内不会重复执行该方法
        QueryWrapper<SysUser> userQueryWrapper=new QueryWrapper<>();
        userQueryWrapper.eq("acct_name",username);
        sysUser = sysUserService.getOne(userQueryWrapper);
        if (sysUser == null) {
            return null;
        }
        SimpleAuthenticationInfo authenticationInfo = new SimpleAuthenticationInfo(
                username, //用户名
                sysUser.getAcctPassword(), //密码
                ByteSource.Util.bytes(sysUser.getSalt()),
                this.getName()  //realm name
        );
        return authenticationInfo;
    }

    //清除缓存
    public void clearCached() {
        PrincipalCollection principals = SecurityUtils.getSubject().getPrincipals();
        super.clearCache(principals);
    }
}
