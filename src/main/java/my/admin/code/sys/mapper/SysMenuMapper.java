package my.admin.code.sys.mapper;

import my.admin.code.sys.entity.SysMenu;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;

import java.util.List;

/**
 * <p>
 * 菜单表 Mapper 接口
 * </p>
 *
 * @author chen
 * @since 2019-05-31
 */
public interface SysMenuMapper extends BaseMapper<SysMenu> {
    List<SysMenu> getMenusByRoleId(Object roleId);
}
