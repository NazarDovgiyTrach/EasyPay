let utiity="";
let inspectorToRemoveId;
let pageContent = $('.content');
let inspectorsList = $('.schedule');
let currentPage=1;
$(document).ready(function () {

    getUtility();
    setInspectorsPagination();
//    getUtilityInspectors();


});

function getUtility() {
    jQuery.ajax({
        url: '/manager/utility/get/',
        type: 'GET',
        dataType: 'json',
        beforeSend:function(){
            showLoader(pageContent);
        },
        success: function (data) {
            utiity=data.name;
            $('#utilityName').html(utiity);
            if (utiity===""){
                $('#addInspectorButton').prop("disabled", true);
            } else {
                $('#addInspectorButton').prop("disabled", false);
            }
        },
        error: function (jqXHR, textStatus, errorThrown) {
            $('#addInspectorButton').prop("disabled", true);
        },
        complete: function(){

            hideLoader(pageContent);
        },

        timeout: 120000,
    });
}

function getUtilityInspectors(page) {

    jQuery.ajax({
        url: '/manager/utility/schedule/inspectors/get/'+page,
        type: 'GET',
        dataType: 'json',

        success: function (data) {
            var scheduleItem="";
            $.each(data, function (index, element) {
                 scheduleItem += "<tr>\n" +
                    "            <td>\n" +
                    "                <a href=\"/manager/schedule/inspector/" + element.id + "/\">" + getFullName(element) + "</a>\n" +
                    "            </td>\n" +
                     "            <td class='text-right'>\n" +
                     '<button data-toggle="modal" data-target="#remove-inspector-modal" class="btn btn-sm btn-danger text-uppercase remove-inspector" data-locale-item=remove type="button" data-id='+element.id+'>' +
                     'Remove <i class="fa fa-trash-o"></i>' +
                     '</button>' + "            </td>\n" +
                    "        </tr>";

                 });
            if (scheduleItem!==""){
            inspectorsList.find('tbody').html(scheduleItem);} else
            { inspectorsList.find('tbody').html("<tr><td data-locale-item='noInspectors'>No inspectors added</td></tr>");}
            createLocalesFilds();
            $('#utilityName').html(utiity);
        }

    });


}

$('#remove-inspector-modal').on('show.bs.modal', function(e) {
    inspectorToRemoveId = $(e.relatedTarget).data('id');

});

$("#removeInspector").click(function () {
    $.ajax({
        url: '/manager/schedule/deleteInspector',
        type: "DELETE",
        data: JSON.stringify(inspectorToRemoveId),
        contentType: "application/json; charset=utf-8",
        complete: function () {
            $('#remove-inspector-modal').modal('hide');
            
        },
        success: function (data, textStatus, xhr) {
            new PNotify({
                title:locales['success'] ,
                text: locales['deleted'],
                type: 'success',
                styling: 'bootstrap3',
                delay: 1000
            });
            setInspectorsPagination();
            getUtilityInspectors(1);
        },
        error: function (data, textStatus, xhr) {
            new PNotify({
                title: locales['error'],
                text: locales['somethingWentWrong'],
                type: 'error',
                styling: 'bootstrap3',
                delay: 1000
            });
    },

});

});

function getFullName(element) {
    return element.name + " " + element.surname;
}


function getFreeInspectors() {
    jQuery.ajax({
        url: '/manager/utility/inspectors/get/free/',
        type: 'GET',
        dataType: 'json',
        success: function (data) {
            var inspectorsFree = "";
            $.each(data, function (index, element) {
                inspectorsFree += "<option " + "value=" + element.id + " >" +
                    element.name + " " + element.surname +
                    "</option>\n"

            });
            if (inspectorsFree!==""){
                $('#busy').addClass('hide');
                $('#inspectors-free').removeClass('hide');
                $('#inspectors-free').html(inspectorsFree);
            } else {
                $('#busy').removeClass('hide');
                $('#inspectors-free').addClass('hide');
            }

        },
        error: function (jqXHR, textStatus, errorThrown) {
        },
        complete: function () {

        },

        timeout: 120000,
    });
}

    function addInspector(inspectors){
    $.ajax({
            url: '/manager/schedule/addInspector',
            type: 'PUT',
            data: JSON.stringify(inspectors),
            contentType: "application/json; charset=utf-8",
            complete: function (data) {
              $('#add-inspector-modal').modal('hide');
            },
            success: function (data, textStatus, xhr) {
                new PNotify({
                    title: locales['success'],
                    text: locales['added'],
                    type: 'success',
                    styling: 'bootstrap3',
                    delay: 1000
                });
                setInspectorsPagination();
                getUtilityInspectors(1);
            },
            error: function (data, textStatus, xhr) {
                new PNotify({
                    title: locales['error'],
                    text: locales['somethingWentWrong'],
                    type: 'error',
                    styling: 'bootstrap3',
                    delay: 1000
                });
            },
        });
    }

    $('#addInspector').click(function(){
        if( $('#inspectors-free :selected').length > 0){
            //build an array of selected values
            var selectednumbers = [];
            $('#inspectors-free :selected').each(function(i, selected) {
                selectednumbers[i] = $(selected).val();
            });
            addInspector(selectednumbers);
        }
    });


function showLoader(element){
    element.addClass('hide');
    $('#loader').show();

 }

function hideLoader(element){

   $('#loader').hide();
   element.removeClass('hide');
}


function setInspectorsPagination() {
    $.get({
        url: '/manager/utility/schedule/inspectors/get/pages',
        success: function (data) {
            if (data<1){
                data=1;
            }
            $('#inspectors-pagination').empty();
            $('#inspectors-pagination').removeData("twbs-pagination");
            $('#inspectors-pagination').unbind("page");
            $('#inspectors-pagination').twbsPagination({
                first: locales["paginationFirst"],
                prev: locales["paginationPrevious"],
                next: locales["paginationNext"],
                last: locales["paginationLast"],
                totalPages: data,
                visiblePages: 10,
                onPageClick: function (event, page) {
                    getUtilityInspectors(page);
                    currentPage=page;
                }
            });
        }
    });
}

