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
    * 字典表
    * </p>
*
* @author chen
* @since 2019-05-31
*/
    @Data
        @EqualsAndHashCode(callSuper = false)
    @Accessors(chain = true)
    @ApiModel(value="SysDict对象", description="字典表")
    public class SysDict implements Serializable {

    private static final long serialVersionUID = 1L;

    @TableId(type = IdType.AUTO)
    private Integer id;

            @ApiModelProperty(value = "字典名称")
    private String dictName;

            @ApiModelProperty(value = "字典所在表")
    private String dictTable;

            @ApiModelProperty(value = "字段所在字段")
    private String dictField;

            @ApiModelProperty(value = "字典码")
    private String dictCode;

            @ApiModelProperty(value = "字典码值")
    private String dictValue;


}
