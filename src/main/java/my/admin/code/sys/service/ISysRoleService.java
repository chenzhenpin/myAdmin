package my.admin.code.sys.service;

import my.admin.code.sys.entity.SysRole;
import com.baomidou.mybatisplus.extension.service.IService;

import java.util.List;

/**
 * <p>
 * 角色表 服务类
 * </p>
 *
 * @author chen
 * @since 2019-05-31
 */
public interface ISysRoleService extends IService<SysRole> {
    List<SysRole> getRolesByUserId(Object userId);
}
