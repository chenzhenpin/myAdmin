package my.admin.code.common.utils;

import java.util.List;

public class PageBean<T> {
    private int code;
    private int total;
    private List<T> data;
    private String msg="查询成功";
    public PageBean(List<T> list){
        this.total=list.size();
        this.data=list;
    }
    public int getCode() {
        return code;
    }

    public void setCode(int code) {
        this.code = code;
    }

    public int getTotal() {
        return total;
    }

    public void setTotal(int total) {
        this.total = total;
    }

    public List<T> getData() {
        return data;
    }

    public void setData(List<T> data) {
        this.data = data;
    }

    public String getMsg() {
        return msg;
    }

    public void setMsg(String msg) {
        this.msg = msg;
    }
}
