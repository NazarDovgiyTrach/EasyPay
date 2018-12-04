package com.softserveinc.ch067.easypay.controller;


import com.softserveinc.ch067.easypay.dto.RatingDTO;
import com.softserveinc.ch067.easypay.dto.UserRatingDTO;
import com.softserveinc.ch067.easypay.model.RatingListItem;
import com.softserveinc.ch067.easypay.model.User;
import com.softserveinc.ch067.easypay.service.IRatingListItemService;
import com.softserveinc.ch067.easypay.service.IRatingService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.List;

@RestController
@RequestMapping("/ratings")
public class RatingController {

    private final IRatingListItemService ratingListItemService;
    private  final IRatingService ratingService;
    @Autowired
    public RatingController(IRatingListItemService ratingListItemService, IRatingService ratingService) {
        this.ratingListItemService = ratingListItemService;
        this.ratingService = ratingService;
    }

    @PutMapping("/rate")
    public ResponseEntity updateRating(@RequestBody @Valid RatingDTO rating, BindingResult result) {
        if (!result.hasErrors()) {
            User rater = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            ratingListItemService.updateUserRating(rater, rating.getUserId(), rating.getRatingValue().doubleValue());
            ratingService.updateUserRating(rating.getUserId());
            return new ResponseEntity<>(HttpStatus.OK);
        }
        return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }

    @GetMapping("/get")
    public List<RatingListItem> getUsersRating(@AuthenticationPrincipal User user) {
        return ratingListItemService.getRatingListByRatedUser(user.getId());

    }

    @GetMapping("/get/history/{pageId}")
    public List<UserRatingDTO> getUsersRatingHistory(@AuthenticationPrincipal User user, @PathVariable int pageId) {
        return ratingListItemService.getUsersToRate(pageId, user.getId());

    }

    @GetMapping("/get/history/pages")
    public Long getPages(@AuthenticationPrincipal User user) {
        return ratingListItemService.getPagesRater(user.getId());
    }

}
