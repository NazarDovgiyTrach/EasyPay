package com.softserveinc.ch067.easypay.aop;

import org.apache.commons.lang3.builder.ReflectionToStringBuilder;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Arrays;

@Aspect
@Component
public class LoggingAspect {

    private static Logger logger = LoggerFactory.getLogger(LoggingAspect.class);

    @Pointcut("execution(* com.softserveinc.ch067.easypay.controller.*.*(..))")
    public void controller() {
         // Pointcut for all controllers
    }

    @Pointcut("execution(* com.softserveinc.ch067.easypay.service.*.*(..))")
    public void service() {
        // Pointcut for all service
    }

    @Pointcut("execution(* com.softserveinc.ch067.easypay.dao.*.*(..))")
    public void dao() {
         // Pointcut for all dao
    }

    @Pointcut("@annotation(com.softserveinc.ch067.easypay.annotation.Loggable)")
    public void loggableAnnotation() {
        // Pointcut for Annotation @Loggable
    }

    @Before(value = "loggableAnnotation()")
    public void logBefore(JoinPoint joinPoint) {
        logger.debug("Entering in Method: {}", joinPoint.getSignature().getName());
        logger.debug("Class Name: {}", joinPoint.getSignature().getDeclaringTypeName());
        logger.debug("Arguments: {}", Arrays.toString(joinPoint.getArgs()));
        logger.debug("Target class: {}", joinPoint.getTarget().getClass().getName());
    }

    @AfterReturning(value = "loggableAnnotation()", returning = "result")
    public void logAfter(JoinPoint joinPoint, Object result) {
        logger.debug("Method Return value: {}", this.getValue(result));
    }

    @Around(value = "loggableAnnotation()")
    public Object logAround(ProceedingJoinPoint joinPoint) throws Throwable {
        long start = System.currentTimeMillis();

        try {
            Object result = joinPoint.proceed();
            long elapsedTime = System.currentTimeMillis() - start;
            String message = String.format("%s executed in %d ms", joinPoint.getSignature(), elapsedTime);
            logger.debug(message);
            return result;
        } catch (IllegalArgumentException e) {
            logger.error("Illegal argument {} in {}", Arrays.toString(joinPoint.getArgs()), joinPoint.getSignature().getName() + "()");
            throw e;
        }
    }

    @AfterThrowing(value = "controller() || service() || dao() || loggableAnnotation()", throwing = "exception")
    public void logAfterThrowing(JoinPoint joinPoint, Throwable exception) {
        logger.error("An exception has been thrown in {}", joinPoint.getSignature().getName());
        logger.error("Cause: {}", exception.getCause());
        logger.error("Exception: ", exception);

    }

    private String getValue(Object result) {
        String returnValue = null;
        if (null != result) {
            if (result.toString().endsWith("@" + Integer.toHexString(result.hashCode()))) {
                returnValue = ReflectionToStringBuilder.toString(result);
            } else {
                returnValue = result.toString();
            }
        }
        return returnValue;
    }

}
