package my.admin.code.sys.service;

import my.admin.code.sys.entity.SysMenu;
import com.baomidou.mybatisplus.extension.service.IService;

import java.util.List;

/**
 * <p>
 * 菜单表 服务类
 * </p>
 *
 * @author chen
 * @since 2019-05-31
 */
public interface ISysMenuService extends IService<SysMenu> {
    List<SysMenu> getMenusByRoleId(Object roleId);
}
