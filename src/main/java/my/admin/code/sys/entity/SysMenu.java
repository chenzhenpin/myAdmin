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
    * 菜单表
    * </p>
*
* @author chen
* @since 2019-05-31
*/
    @Data
        @EqualsAndHashCode(callSuper = false)
    @Accessors(chain = true)
    @ApiModel(value="SysMenu对象", description="菜单表")
    public class SysMenu implements Serializable {

    private static final long serialVersionUID = 1L;

    @TableId(type = IdType.AUTO)
    private Integer id;

    private Integer pid;

            @ApiModelProperty(value = "菜单码")
    private String menuCode;

            @ApiModelProperty(value = "菜单类型1菜单目录，2菜单页")
    private String menuType;

            @ApiModelProperty(value = "菜单层级")
    private Integer menuLevel;

    private String menuName;

            @ApiModelProperty(value = "菜单地址")
    private String menuUrl;

            @ApiModelProperty(value = "菜单排序")
    private Integer menuSort;

            @ApiModelProperty(value = "菜单图标")
    private String menuIcon;

    private Integer curNum;

            @ApiModelProperty(value = "资源标识")
    private String resourceCode;


}
