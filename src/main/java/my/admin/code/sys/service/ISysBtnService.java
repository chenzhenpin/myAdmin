package my.admin.code.sys.service;

import my.admin.code.sys.entity.SysBtn;
import com.baomidou.mybatisplus.extension.service.IService;

import java.util.List;

/**
 * <p>
 * 按钮表 服务类
 * </p>
 *
 * @author chen
 * @since 2019-05-31
 */
public interface ISysBtnService extends IService<SysBtn> {
    List<SysBtn> getBtnsByRoleId(Object roleId);
}
