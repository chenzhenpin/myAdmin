package my.admin.code.sys.entity;

    import com.baomidou.mybatisplus.annotation.IdType;
    import com.baomidou.mybatisplus.annotation.TableId;
    import java.io.Serializable;
    import io.swagger.annotations.ApiModel;
    import io.swagger.annotations.ApiModelProperty;
    import lombok.Data;
    import lombok.EqualsAndHashCode;
    import lombok.experimental.Accessors;

/**
* <p>
    * 用户表
    * </p>
*
* @author chen
* @since 2019-05-31
*/
    @Data
        @EqualsAndHashCode(callSuper = false)
    @Accessors(chain = true)
    @ApiModel(value="SysUser对象", description="用户表")
    public class SysUser implements Serializable {

    private static final long serialVersionUID = 1L;

    @TableId(type = IdType.AUTO)
    private Integer id;

            @ApiModelProperty(value = "账号")
    private String acctName;

            @ApiModelProperty(value = "姓名")
    private String realName;

            @ApiModelProperty(value = "账号状态")
    private String acctStatus;

            @ApiModelProperty(value = "账号类型")
    private String acctType;

            @ApiModelProperty(value = "账号密码")
    private String acctPassword;

            @ApiModelProperty(value = "部门id")
    private Integer deptId;

            @ApiModelProperty(value = "电话")
    private String phone;

            @ApiModelProperty(value = "地址")
    private String address;

            @ApiModelProperty(value = "加盐")
    private String salt;


}
