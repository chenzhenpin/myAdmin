package my.admin.code.common.numeration;

import lombok.Getter;

@Getter
public enum ExceptionEnum {
    ERROR_SQL(10001, "数据库操作异常"),
    ERROR_NOFOUND_DATA(10002, "找不到该记录"),
    ERROR_EMPTY_PARAM(10003, "参数为空"),
    ERROR_NO_PERMIT(10004, "操作不允许"),
    ERROR_NO_AUTH(10005, "无该权限");
    private Integer code;

    private String message;
    ExceptionEnum(int code, String message){
        this.code=code;
        this.message=message;
    }
}