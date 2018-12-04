var colCount = 0;
let pageContent = $('.content');
let currentPage=1;
$(document).ready(function () {
    setPagination();
});

function countClolums() {
    colCount = 0;
    $('tr:nth-child(1) th').each(function () {
        if ($(this).attr('colspan')) {
            colCount += +$(this).attr('colspan');
        } else {
            colCount++;
        }
    });
}

function getUsersToRate(page) {
    let userList="";
    jQuery.ajax({
        url: '/ratings/get/history/'+page,
        type: 'GET',
        dataType: 'json',
        beforeSend:function(){
            showLoader(pageContent);
        },
        success: function (data) {
           countClolums();
            $('#user-list-rating').find('tbody').html('<tr><td>'+locales["noPeopleToRate"]+'</td></tr>');
            $.each(data, function (index, element) {
                userList += "<tr>\n" +
                    "<td>\n" +element.name+" "+element.surname+ "</td>\n";
                if (element.utilityName!==""&&colCount>3){
                    userList+="<td>\n"+element.utilityName+"</td>\n";
                }
                userList += "<td>\n"+"<input type='hidden' class='rating' data-readonly value=" +element.rating+"data-fractions=2 />"+"</td>\n" +
                    "<td>\n" +"<input type='hidden' class='rating' onchange='rate(this)' value="+element.raterRatingValue+" data-fractions=2 data-id="+element.id+" />" +"</td>\n" +
                    "        </tr>";

            });
            if(userList!==""){
            $('#user-list-rating').find('tbody').html(userList);}

            $('.rating').rating({
                start:0,
                stop:5,
                filled: 'fa fa-star',
                empty: 'fa fa-star-o'}
            );



        },
        error: function (jqXHR, textStatus, errorThrown) {
            new PNotify({
                title: locales['error'],
                text: locales['somethingWentWrong'],
                type: 'error',
                styling: 'bootstrap3',
                delay: 1000
            });
        },
        complete: function(){
            hideLoader(pageContent);
        },

        timeout: 120000,
    });
}

function showLoader(element){
    element.addClass('hide');
    $('#loader').removeClass('hide');

}

function hideLoader(element){

    $('#loader').addClass('hide');
    element.removeClass('hide');
}



function rateUser(rating){    $.ajax({
    url: '/ratings/rate',
    type: 'PUT',
    data: JSON.stringify(rating),
    contentType: "application/json; charset=utf-8",
    complete: function (data) {
    },
    success: function (data, textStatus, xhr) {
        new PNotify({
            title: locales['success'],
            type: 'success',
            styling: 'bootstrap3',
            delay: 1000
        });
        getUsersToRate(currentPage);
    },
    error: function (data, textStatus, xhr) {
        new PNotify({
            title: locales['error'],
            type: 'error',
            styling: 'bootstrap3',
            delay: 1000
        });
        getUsersToRate(currentPage);
    },
});
}



function rate(e) {
    let  rating = {};
    rating.userId=$(e).data('id');
    rating.ratingValue=$(e).val();
    rateUser(rating);
}

function setPagination() {
    $.get({
        url: '/ratings/get/history/pages',
        success: function (data) {
            if (data<1){
                data=1;
            }
            $('#rating-pagination').twbsPagination({
                first: locales["paginationFirst"],
                prev: locales["paginationPrevious"],
                next: locales["paginationNext"],
                last: locales["paginationLast"],
                totalPages: data,
                visiblePages: 10,
                onPageClick: function (event, page) {
                    getUsersToRate(page);
                    currentPage=page;
                }
            });
        }
    });
}
