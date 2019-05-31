package my.admin.code.common.utils;

import javax.servlet.http.HttpServletRequest;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

public class ParamMap {
    public static  Map<String,Object> paramsToMapObject(HttpServletRequest request){
        Enumeration<String> params=request.getParameterNames();
        Map<String,Object> paramMap=new HashMap<>();
        while (params.hasMoreElements()){
            String param=params.nextElement();
            paramMap.put(param,request.getParameter(param));
        }
        return paramMap;
    }
    public static  Map<String,String> paramsToMapString(HttpServletRequest request){
        Enumeration<String> params=request.getParameterNames();
        Map<String,String> paramMap=new HashMap<>();
        while (params.hasMoreElements()){
            String param=params.nextElement();
            paramMap.put(param,request.getParameter(param));
        }
        return paramMap;
    }
}
