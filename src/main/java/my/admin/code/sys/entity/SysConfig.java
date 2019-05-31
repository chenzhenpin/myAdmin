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
    * 系统配置表
    * </p>
*
* @author chen
* @since 2019-05-31
*/
    @Data
        @EqualsAndHashCode(callSuper = false)
    @Accessors(chain = true)
    @ApiModel(value="SysConfig对象", description="系统配置表")
    public class SysConfig implements Serializable {

    private static final long serialVersionUID = 1L;

    @TableId(type = IdType.AUTO)
    private Integer id;

    private String confName;

            @ApiModelProperty(value = "配置标识")
    private String confCode;

            @ApiModelProperty(value = "配置值")
    private String confValue;

            @ApiModelProperty(value = "配置说明")
    private String confDesc;

            @ApiModelProperty(value = "配置状态（1可用，2不可用）")
    private String confStatus;


}
