let histories = [];
let currentPage = 1;
let setHistoriesURL;
let googleDriveViewFileURL = 'https://drive.google.com/file/d/{fileId}/view';

$('#checkall').change(function () {
    $('.checkthis').prop('checked',this.checked);
});

$(document).on('change', '.checkthis', function(){
    if ($('.checkthis:checked').length == $('.checkthis').length){
        $('#checkall').prop('checked',true);
    }
    else {
        $('#checkall').prop('checked',false);
    }
});

$('#select-address').on('change', function(e){
    $('#historyTable > tbody').html("");
    setHistoriesURL = '/user/address/' + $('#select-address').val() + '/utility/' + $('#select-utility').val() + '/payments/history/';
    setHistories(setHistoriesURL, 1);
});

$('#select-utility').on('change', function(e){
    $('#historyTable > tbody').html("");
    setHistoriesURL = '/user/address/' + $('#select-address').val() + '/utility/' + $('#select-utility').val() + '/payments/history/';
    setHistories(setHistoriesURL, 1);
});

$(document).ready(function(){
    setData();
});

function setData() {
    $('title').html(locales.userPaymentsHistoryTitle);
    let addresses = [];

    $.ajax({
        type: 'GET',
        url: '/listById',
        success: function (response) {
            addresses = response;
            $.each(addresses, function () {
                let template = $.isNumeric(this.flat.number) ? "{0} {1}/{2}, {3}, {4}" : "{0} {1}{2}, {3}, {4}";
                $('#select-address').append($("<option></option>")
                    .attr("value", this.id)
                    .text(getFullAddress(this)));
            });

            let addressId = $('#select-address').val();
            let utilities = [];
            $.ajax({
                type: 'GET',
                url: '/address/' + addressId + '/utilities',
                success: function (response) {
                    utilities = response;
                    $.each(utilities, function () {
                        $('#select-utility').append($("<option></option>")
                            .attr("value", this.id)
                            .text(this.name));
                    });

                    setHistoriesURL = '/user/address/' + $('#select-address').val() + '/utility/' + $('#select-utility').val() + '/payments/history/';
                    setPagination();
                },
                error: function (jqXHR, textStatus, errorThrown) {

                },

                timeout: 120000
            });

        },
        error: function (jqXHR, textStatus, errorThrown) {

        },

        timeout: 120000
    });

    $("[data-toggle=tooltip]").tooltip();
}

function setPagination() {
    $.get({
        url: '/user/address/' + $('#select-address').val() + '/utility/' + $('#select-utility').val() + '/payments/history/pages',
        success: function (data) {
            if (data<1){
                data=1;
            }
            if (data == 1){
                $('#payments-history-pagination').addClass('hidden');
            }
            $('#payments-history-pagination').twbsPagination({
                totalPages: data,
                visiblePages: 10,
                first: locales["paginationFirst"],
                prev: locales["paginationPrevious"],
                next: locales["paginationNext"],
                last: locales["paginationLast"],
                onPageClick: function (event, page) {
                    $('#historyTable > tbody').html("");
                    let url = '/user/address/' + $('#select-address').val() + '/utility/' + $('#select-utility').val() + '/payments/history/';
                    setHistories(url, page);
                    currentPage=page;
                }
            });
           // setHistories(setHistoriesURL, currentPage);
        }
    });
}

function setHistories(url, page){
    hideFormShowLoader();
    $.ajax({
        type: 'GET',
        url: url + page,
        success: function (response) {
            histories = response;
            for (var i = 0; i < histories.length; i++) {
                $('#historyTable > tbody').append(
                    '<tr class="myRow">' +
                    '<td class="historyDate">' + new Date(histories[i].payDate).toLocaleDateString() + '</td>' +
                    '<td class="historySum">' + histories[i].paymentSum + '</td>' +
                    '<td class="historyView">' + '<a class="view-check btn btn-primary" href="' + googleDriveViewFileURL.replace("{fileId}", histories[i].googleDriveFileId) + '" data-id="' + histories[i].googleDriveFileId + '">' + locales.viewCheck + '</a>'
                    + '</tr>'
                )
            }
            hideLoaderShowForm();
        },
        error: function (error) {
            hideLoaderShowForm();
            notify(locales["error"], locales[error.responseJSON], 'error', 3000);
        },

        timeout: 120000
    });
}

/*$(document).on('click', '.view-check', function(){
        /!*$.ajax({
            type: 'GET',
            url: '/user/payments/history/check?fileId=' + $(this).attr('data-id'),
            success: function (response) {
                window.location.href = response;
            },
            error: function (jqXHR, textStatus, errorThrown) {

            },

            timeout: 120000
        });*!/
});*/

let notify = function notify(title, text, type, delay){
    new PNotify({
        title: title,
        text: text,
        type: type,
        styling: 'bootstrap3',
        delay: delay
    });
};

function hideFormShowLoader(){
    $('#content').removeClass('show');
    $('#content').addClass('hide');
    $('#loading').removeClass('hide');
    $('#loading').addClass('show');
}

function hideLoaderShowForm(){
    $('#loading').removeClass('show');
    $('#loading').addClass('hide');
    $('#content').removeClass('hide');
    $('#content').addClass('show');
}