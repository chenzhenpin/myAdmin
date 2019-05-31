package my.admin.code.common.exception;

import my.admin.code.common.numeration.ExceptionEnum;


public class WebException extends RuntimeException{

    private Integer code;

    public WebException(ExceptionEnum exceptionEnum) {
        super(exceptionEnum.getMessage());

        this.code = exceptionEnum.getCode();
    }

    public WebException(Integer code, String message) {
        super(message);
        this.code = code;
    }

    public Integer getCode() {
        return code;
    }

}