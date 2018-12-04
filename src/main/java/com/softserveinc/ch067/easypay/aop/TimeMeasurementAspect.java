package com.softserveinc.ch067.easypay.aop;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Aspect
@Component
public class TimeMeasurementAspect {

    private static Logger logger = LoggerFactory.getLogger(LoggingAspect.class);

    @Pointcut("@annotation(com.softserveinc.ch067.easypay.annotation.TimeMeasurement)")
    public void loggableAnnotation() {
        // Pointcut for Annotation @TimeMeasurement
    }

    @Around("loggableAnnotation()")
    public Object getTimeMeasurement(ProceedingJoinPoint pjp) throws Throwable {
        long start = System.currentTimeMillis();

        logger.debug("Going to call the method.");
        Object output = pjp.proceed();

        logger.debug("Method execution completed.");
        long elapsedTime = System.currentTimeMillis() - start;

        logger.debug("Method execution time: " + elapsedTime + " milliseconds.");
        return output;
    }

}
