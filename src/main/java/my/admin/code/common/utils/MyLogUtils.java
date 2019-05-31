package my.admin.code.common.utils;

import my.admin.code.common.exception.WebException;
import org.slf4j.Logger;

import javax.servlet.http.HttpServletRequest;
import java.util.Enumeration;

public class MyLogUtils {
    public static void error(Logger logger, HttpServletRequest request, WebException e){
        Enumeration<String> paramsEnumeration=request.getParameterNames();
        StringBuffer params=new StringBuffer();
        while (paramsEnumeration.hasMoreElements()){
            String key=paramsEnumeration.nextElement();
            params=params.append(key);
            params=params.append(":");
            params=params.append(request.getParameter(key));
            if (paramsEnumeration.hasMoreElements()){
                params=params.append("&");
            }
        }
        logger.error(request.getRequestURL()+"|"+params);
        logger.error("  code:"+e.getCode()+"  msg:"+e.getMessage(),e);
    }

}
