package my.admin.code.sys.mapper;

import my.admin.code.sys.entity.SysRole;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;

import java.util.List;

/**
 * <p>
 * 角色表 Mapper 接口
 * </p>
 *
 * @author chen
 * @since 2019-05-31
 */
public interface SysRoleMapper extends BaseMapper<SysRole> {
    List<SysRole> getRolesByUserId(Object userId);
}
