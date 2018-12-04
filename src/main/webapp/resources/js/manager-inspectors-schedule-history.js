let historyContent = $('.history-content');
let currentPage;
$(document).ready(function () {
setPaginationSHC();
setPaginationSHP();
getCurrentMonthHistoryStats();
getPreviousMonthHistoryStats();
});


function getCurrentMonthHistory(page){
    jQuery.ajax({
        url: "/manager/schedule/inspector/"+getIdByUrl()+"/history/current/"+page,
        type: "GET",
        contentType: 'application/json; charset=utf-8',
        beforeSend: function(){
            showLoader(historyContent);
        },
        success: function (resultData) {

            $('#scheduleHistoryCurrent').find('tbody').html("<tr><td colspan='5' data-locale-item='noHistory'></td></tr>");

            if(resultData!==null){
            let scheduleItem="";
            $.each(resultData, function(i, sh) {
                $('#inspectorName').html(sh.inspector.name+" "+ sh.inspector.surname);
                var template = $.isNumeric(sh.address.flat.number) ? "{0} {1}/{2}\n{3},\n{4}" : "{0} {1}{2}\n{3},\n{4}";
                scheduleItem += "<tr>\n" +
                    "            <td>" + getFullAddressWithTemplate(sh.address, template) + "</td>\n" +
                    "            <td>" + formatDate(sh.eventDate) + "</td>\n";
                if (sh.status==="OVERDUE"){
                    scheduleItem+="            <td class='bg-red text-center' data-locale-item='overdue'></td>\n" ;
                }
                if (sh.status==="DONE"){
                    scheduleItem+="            <td class='bg-green text-center' data-locale-item='done'></td>\n" ;
                }

                if (sh.status==="CANCELED"){
                    scheduleItem+="            <td class='bg-orange text-center' data-locale-item='canceled'></td>\n" ;
                }

                scheduleItem+= "            <td>" + formatDate(sh.submitDate) + "</td>\n" +
                    "            <td>" + sh.comment + "</td>\n" +
                    "        </tr>";

            });

            if(scheduleItem!==""){
                $('#scheduleHistoryCurrent').find('tbody').html(scheduleItem);
            }}
            createLocalesFilds();

        },
        error: function (jqXHR, textStatus, errorThrown) {
        },
        complete: function(){

           hideLoader(historyContent);
        },

        timeout: 120000,
    });
}


function getPreviousMonthHistory(page){
    jQuery.ajax({
        url: "/manager/schedule/inspector/"+getIdByUrl()+"/history/previous/"+page,
        type: "GET",
        contentType: 'application/json; charset=utf-8',
        success: function (resultData) {
            let scheduleItem="";
            $('#scheduleHistoryPrevious').find('tbody').html("<tr><td colspan='5' data-locale-item='noHistory'></td></tr>");
            if (resultData!==null) {
                $.each(resultData, function (i, sh) {
                    var template = $.isNumeric(sh.address.flat.number) ? "{0} {1}/{2}\n{3},\n{4}" : "{0} {1}{2}\n{3},\n{4}";
                    scheduleItem += "<tr>\n" +
                        "            <td>" + getFullAddressWithTemplate(sh.address, template) + "</td>\n" +
                        "            <td>" + formatDate(sh.eventDate) + "</td>\n";
                    if (sh.status === "OVERDUE") {

                        scheduleItem += "            <td class='bg-red text-center' data-locale-item='overdue'></td>\n";
                    }
                    if (sh.status === "DONE") {

                        scheduleItem += "            <td class='bg-green text-center' data-locale-item='done'></td>\n";
                    }

                    if (sh.status === "CANCELED") {

                        scheduleItem += "            <td class='bg-orange text-center' data-locale-item='canceled'></td>\n";
                    }

                    scheduleItem += "            <td>" + formatDate(sh.submitDate) + "</td>\n" +
                        "            <td>" + sh.comment + "</td>\n" +
                        "        </tr>";


                });

                if (scheduleItem !== "") {
                    $('#scheduleHistoryPrevious').find('tbody').html(scheduleItem);
                }
            }
            createLocalesFilds();
        },
        error: function (jqXHR, textStatus, errorThrown) {
        },
        complete: function(){

            $('#loader-history-past').hide();
        },

        timeout: 120000,
    });
}

function formatDate(date) {
    let d = new Date(date);
    let formattedDate = d.getDate() + "." + (d.getMonth() + 1) + "." + d.getFullYear();
    return formattedDate;
}

/*function getFullAddress(address){
    return 'Reg. '+address.region.name+', '+address.city.name+', '+address.street.name+' Str. '+address.house.number+'/'+address.flat.number;
}*/


function getIdByUrl() {
    let url = $(location).attr('pathname');
    let urlParts = url.split("/");
    return urlParts[4];
}


function getInspectorName(){
    jQuery.ajax({
        url: "/manager/inspector/get/"+getIdByUrl(),
        type: "GET",
        contentType: 'application/json; charset=utf-8',
        success: function (resultData) {
            $('.js-name-inspector').html(resultData.name+" "+resultData.surname);

        },
        error: function (jqXHR, textStatus, errorThrown) {
    },
    complete: function() {


    }


})
}

function showLoader(element){
    element.addClass('hide');
    $('#loader').show();

}

function hideLoader(element){

    $('#loader').hide();
    element.removeClass('hide');
}

function setPaginationSHC() {
    $.get({
        url: "/manager/schedule/inspector/"+getIdByUrl()+"/history/current/pages",
        success: function (data) {
            if (data<1){
                data=1;
            }
            $('#shc-pagination').twbsPagination({
                totalPages: data,
                visiblePages: 10,
                first: locales["paginationFirst"],
                prev: locales["paginationPrevious"],
                next: locales["paginationNext"],
                last: locales["paginationLast"],
                onPageClick: function (event, page) {
                    getCurrentMonthHistory(page);
                    currentPage=page;
                }
            });
        }
    });
}

function setPaginationSHP() {
    $.get({
        url: "/manager/schedule/inspector/"+getIdByUrl()+"/history/previous/pages",
        success: function (data) {
            if (data<1){
                data=1;
            }
            $('#shp-pagination').twbsPagination({
                totalPages: data,
                visiblePages: 10,
                first: locales["paginationFirst"],
                prev: locales["paginationPrevious"],
                next: locales["paginationNext"],
                last: locales["paginationLast"],
                onPageClick: function (event, page) {
                    getPreviousMonthHistory(page);
                    currentPage=page;
                }
            });
        }
    });
}



function getCurrentMonthHistoryStats(){
    jQuery.ajax({
        url: "/manager/schedule/inspector/"+getIdByUrl()+"/history/current/",
        type: "GET",
        contentType: 'application/json; charset=utf-8',
        beforeSend: function(){
            showLoader(historyContent);
        },
        success: function (resultData) {
            let overdue = 0;
            let done = 0;
            let canceled =0;
            let appointmentsSum;
            $.each(resultData, function(i, sh) {
                        if (sh.status === "OVERDUE") {
                            overdue++;
                        }
                        if (sh.status === "DONE") {
                            done++;
                        }

                        if (sh.status === "CANCELED") {
                            canceled++;
                        }
                    });
                 appointmentsSum = done+canceled+overdue;
                 if (appointmentsSum!==0){
                $('#done').html(done);
                $('#canceled').html(canceled);
                $('#overdue').html(overdue);

                $('#done-bar').css('width', done/appointmentsSum*100+'%');
                $('#canceled-bar').css('width', canceled/appointmentsSum*100+'%');
                $('#overdue-bar').css('width', overdue/appointmentsSum*100+'%');

            createLocalesFilds();}

        },
        error: function (jqXHR, textStatus, errorThrown) {
        },
        complete: function(){

        },

        timeout: 120000,
    });
}


function getPreviousMonthHistoryStats(){
    jQuery.ajax({
        url: "/manager/schedule/inspector/"+getIdByUrl()+"/history/previous/",
        type: "GET",
        contentType: 'application/json; charset=utf-8',
        success: function (resultData) {
            let overdue = 0;
            let done = 0;
            let canceled =0;
            let appointmentsSum;
            $.each(resultData, function(i, sh) {
                if (sh.status==="OVERDUE"){
                    overdue++;
                }
                if (sh.status==="DONE"){
                    done++;
                }

                if (sh.status==="CANCELED"){
                    canceled++;
                }
            });
                appointmentsSum = done+canceled+overdue;
                if (appointmentsSum!==0) {
                    $('#done-p').html(done);
                    $('#canceled-p').html(canceled);
                    $('#overdue-p').html(overdue);

                    $('#done-bar-p').css('width', done / appointmentsSum * 100 + '%');
                    $('#canceled-bar-p').css('width', canceled / appointmentsSum * 100 + '%');
                    $('#overdue-bar-p').css('width', overdue / appointmentsSum * 100 + '%');
                    createLocalesFilds();
                }

        },
        error: function (jqXHR, textStatus, errorThrown) {
        },
        complete: function(){

        },

        timeout: 120000,
    });
}