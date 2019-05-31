package my.admin.code.common.exception.handle;

import my.admin.code.common.exception.WebException;
import my.admin.code.common.utils.CommonUtils;
import my.admin.code.common.utils.MyLogUtils;
import my.admin.code.common.utils.ResData;
import my.admin.code.common.utils.SysConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


@ControllerAdvice
public class WebExceptionHandler {
    Logger log = LoggerFactory.getLogger(WebExceptionHandler.class);

    @ExceptionHandler(WebException.class)
    public ModelAndView WebExceptionHandler(HttpServletRequest request, HttpServletResponse response, WebException e)throws Exception {

        ResData error=ResData.fail().setCode(e.getCode()).setMsg(e.getMessage());
        if (e.getCode().equals(ResData.NO_LOGIN_CODE)){
            Cookie removeCookie=new Cookie(SysConstants.TOKEN,"");
            response.addCookie(removeCookie);
            CommonUtils.writeJson(response, error);
            return null;
        }else if(e.getCode().equals(ResData.NO_LOGIN_CODE)){
            request.getSession().setAttribute(SysConstants.SYS_BEFORE_URL, request.getRequestURL());
            response.sendRedirect(SysConstants.SYS_LOGIN_URL);
            return null;
        }
        MyLogUtils.error(log,request,e);
        String header = request.getHeader("X-Requested-With");
        if ("XMLHttpRequest".equalsIgnoreCase(header)) {
            CommonUtils.writeJson(response, error);
            return null;
        } else {
            ModelAndView mv = new ModelAndView("mapper.sys/500");
            mv.addObject("message", error.getMsg());
            return mv;
        }

    }

}
