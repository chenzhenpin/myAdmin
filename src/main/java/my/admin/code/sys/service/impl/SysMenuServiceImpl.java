package my.admin.code.sys.service.impl;

import my.admin.code.common.exception.WebException;
import my.admin.code.common.numeration.ExceptionEnum;
import my.admin.code.sys.entity.SysMenu;
import my.admin.code.sys.mapper.SysMenuMapper;
import my.admin.code.sys.service.ISysMenuService;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.validation.constraints.NotBlank;
import java.util.List;

/**
 * <p>
 * 菜单表 服务实现类
 * </p>
 *
 * @author chen
 * @since 2019-05-31
 */
@Service
public class SysMenuServiceImpl extends ServiceImpl<SysMenuMapper, SysMenu> implements ISysMenuService {
    @Autowired
    private SysMenuMapper sysMenuMapper;
    @Override
    public List<SysMenu> getMenusByRoleId(@NotBlank Object roleId) {
//        if (roleId==null || StringUtils.isBlank(roleId.toString())){
//            throw new WebException(ExceptionEnum.ERROR_EMPTY_PARAM);
//        }
        return sysMenuMapper.getMenusByRoleId(roleId);
    }
}
