package my.admin.code.sys.mapper;

import my.admin.code.sys.entity.SysBtn;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;

import java.util.List;

/**
 * <p>
 * 按钮表 Mapper 接口
 * </p>
 *
 * @author chen
 * @since 2019-05-31
 */
public interface SysBtnMapper extends BaseMapper<SysBtn> {
    List<SysBtn> getBtnsByRoleId(Object roleId);
}
