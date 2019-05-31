package my.admin.code.common.utils;

public class ResData {
    public static final int NO_LOGIN_CODE=10000;//未登录
    public static final int PARAM_EMPTY_CODE=203;//参数为空
    private Boolean success;
    private Integer code;
    private String msg;
    private Object data;
    public ResData(){}
    public static ResData create(){
        return new ResData();
    }
    public static ResData ok(){
        return new ResData().setSuccess(true).setMsg("成功");
    }
    public static ResData fail(){
        return new ResData().setSuccess(false).setMsg("失败");
    }
    public static ResData paramEmpty(){
        return new ResData().setSuccess(false).setCode(ResData.PARAM_EMPTY_CODE).setMsg("参数为空");
    }
    public Boolean getSuccess() {
        return success;
    }

    public ResData setSuccess(Boolean success) {
        this.success = success;
        return this;
    }

    public Integer getCode() {
        return code;
    }

    public ResData setCode(Integer code) {
        this.code = code;
        return this;
    }

    public String getMsg() {
        return msg;
    }

    public ResData setMsg(String msg) {
        this.msg = msg;
        return this;
    }

    public Object getData() {
        return data;
    }

    public ResData setData(Object data) {
        this.data = data;
        return this;
    }
}
