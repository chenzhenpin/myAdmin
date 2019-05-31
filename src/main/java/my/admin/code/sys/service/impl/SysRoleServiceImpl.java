package my.admin.code.sys.service.impl;

import my.admin.code.common.exception.WebException;
import my.admin.code.common.numeration.ExceptionEnum;
import my.admin.code.sys.entity.SysRole;
import my.admin.code.sys.mapper.SysRoleMapper;
import my.admin.code.sys.service.ISysRoleService;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.validation.constraints.NotBlank;
import java.util.List;

/**
 * <p>
 * 角色表 服务实现类
 * </p>
 *
 * @author chen
 * @since 2019-05-31
 */
@Service
public class SysRoleServiceImpl extends ServiceImpl<SysRoleMapper, SysRole> implements ISysRoleService {
    @Autowired
    private SysRoleMapper sysRoleMapper;
    @Override
    public List<SysRole> getRolesByUserId(@NotBlank Object userId) {
//        if (userId==null || StringUtils.isBlank(userId.toString())){
//            throw new WebException(ExceptionEnum.ERROR_EMPTY_PARAM);
//        }
        return sysRoleMapper.getRolesByUserId(userId);
    }
}
