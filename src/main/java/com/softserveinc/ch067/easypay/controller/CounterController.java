package com.softserveinc.ch067.easypay.controller;

import com.softserveinc.ch067.easypay.exception.ForbiddenCounterActionException;
import com.softserveinc.ch067.easypay.model.Counter;
import com.softserveinc.ch067.easypay.model.Role;
import com.softserveinc.ch067.easypay.model.User;
import com.softserveinc.ch067.easypay.service.ICounterService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
public class CounterController {

    private ICounterService counterService;

    private static final String WRONG_COUNTER_VALUE = "You have specified wrong counter value!";
    private static final String FIXED_COUNTER_VALUES_IMMUTABLE = "The counter is fixed and you can't change its values!";
    private static final String COUNTER_NOT_YOURS = "You are trying to update a value of counter that you have no access to!";
    private static final String COUNTER_ALREADY_INITIALIZED = "Counter was already initialized!";
    private static final String UNACTIVE_COUNTER_NOT_INITIALIZABLE = "Unactive counter cannot be initialized!";

    private static final String RESPONSE_WRONG_COUNTER_VALUE = "responseWrongCounterValueSet";
    private static final String RESPONSE_FIXED_COUNTER_VALUES_IMMUTABLE = "responseFixedCounterImmutable";
    private static final String RESPONSE_COUNTER_NOT_YOURS = "responseCounterNotYours";
    private static final String RESPONSE_SERVER_ERROR = "responseServerError";
    private static final String RESPONSE_COUNTER_UPDATED = "responseCounterUpdated";
    private static final String RESPONSE_COUNTER_ALREADY_INITIALIZED = "responseCounterAlreadyInitialized";
    private static final String RESPONSE_UNACTIVE_COUNTER_NOT_INITIALIZABLE = "responseUnactiveCounterNotInitializable";

    @Autowired
    public CounterController(ICounterService counterService) {
        this.counterService = counterService;
    }

    @GetMapping("/counters")
    public List<Counter> getAll(){
        return counterService.getAll();
    }

    @PostMapping(value = {"/inspector/counter/{id}/value/update",
                            "/user/counter/{id}/value/update"})
    public ResponseEntity updateCounterCurrentValue(@PathVariable("id") Long id, @RequestParam("value") Long newValue,
                                   @AuthenticationPrincipal User user){
        Counter counter = counterService.getById(id);

        if (newValue <= 0 || newValue < counter.getOldValue())
            throw new ForbiddenCounterActionException(WRONG_COUNTER_VALUE);

        if (counter.isFixed())
            throw new ForbiddenCounterActionException(FIXED_COUNTER_VALUES_IMMUTABLE);

        if (!counter.getUser().getId().equals(user.getId()) && !user.getRole().equals(Role.INSPECTOR))
            throw new ForbiddenCounterActionException(COUNTER_NOT_YOURS);

        counterService.updateCounterCurrentValue(id, newValue);
        return ResponseEntity.ok(RESPONSE_COUNTER_UPDATED);
    }

    @PostMapping("/inspector/counter/{id}/status/update")
    public ResponseEntity updateCounterStatus(@PathVariable("id") Long id, @RequestParam("value") boolean active){
        counterService.updateCounterStatus(id, active);
        return ResponseEntity.ok(RESPONSE_COUNTER_UPDATED);
    }

    @PostMapping("/inspector/counter/{id}/type/update")
    public ResponseEntity updateCounterType(@PathVariable("id") Long id, @RequestParam("value") boolean fixed){
        counterService.updateCounterType(id, fixed);
        return ResponseEntity.ok(RESPONSE_COUNTER_UPDATED);
    }

    @PostMapping("/inspector/counter/{id}/init")
    public ResponseEntity initCounterValues(@PathVariable("id") Long id){
        Counter databaseCounter = counterService.getById(id);
        if (!databaseCounter.isActive()){
            throw new ForbiddenCounterActionException(UNACTIVE_COUNTER_NOT_INITIALIZABLE);
        }
        if (databaseCounter.isActive() && databaseCounter.getCurrentValue() > 0){
            throw new ForbiddenCounterActionException(COUNTER_ALREADY_INITIALIZED);
        }
        counterService.initWithValues(databaseCounter);
        return ResponseEntity.ok(RESPONSE_COUNTER_UPDATED);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleException(Exception e){
        if (e instanceof ForbiddenCounterActionException){
            switch (e.getMessage()){
                case WRONG_COUNTER_VALUE:
                    return new ResponseEntity<>(RESPONSE_WRONG_COUNTER_VALUE,
                                                HttpStatus.BAD_REQUEST);

                case FIXED_COUNTER_VALUES_IMMUTABLE:
                    return new ResponseEntity<>(RESPONSE_FIXED_COUNTER_VALUES_IMMUTABLE,
                                                HttpStatus.BAD_REQUEST);

                case COUNTER_NOT_YOURS:
                    return new ResponseEntity<>(RESPONSE_COUNTER_NOT_YOURS,
                                                HttpStatus.BAD_REQUEST);

                case COUNTER_ALREADY_INITIALIZED:
                    return new ResponseEntity<>(RESPONSE_COUNTER_ALREADY_INITIALIZED,
                                                HttpStatus.BAD_REQUEST);

                case UNACTIVE_COUNTER_NOT_INITIALIZABLE:
                    return new ResponseEntity<>(RESPONSE_UNACTIVE_COUNTER_NOT_INITIALIZABLE,
                                                HttpStatus.BAD_REQUEST);
            }
        }
        return new ResponseEntity<>(RESPONSE_SERVER_ERROR,
                HttpStatus.INTERNAL_SERVER_ERROR);
    }

}
