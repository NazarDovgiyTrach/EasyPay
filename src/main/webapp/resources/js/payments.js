let utilityId;
let debtId;
let counterToUpdId;
let totalSumToPay = 0;
let oldValue;

let handler = StripeCheckout.configure({
    key: 'pk_test_GuEcLJKjHqJ67BjsQ9zSvh5W',
    image: 'https://stripe.com/img/documentation/checkout/marketplace.png',
    locale: 'auto',
    token: function(token){
        $('#paymentSumModal').modal('hide');
        hideFormShowLoader();
        $.ajax({
            url: '/user/payWithCard?sum=' + totalSumToPay,
            type: 'POST',
            data: JSON.stringify(token.id),
            contentType: "application/json",
            success: function(response){
                if ($('input[name=options]:radio:checked').filter(":checked").val() == 'download'){
                    payAndDownloadCheck();
                }else if ($('input[name=options]:radio:checked').filter(":checked").val() == 'send'){
                    payAndSendCheck();
                }

            },
            error: function (error) {
                notify(locales["error"], locales[error.responseJSON], 'error', 3000);
            },

            timeout: 120000
        });
    }
});

document.getElementById('pay').addEventListener('click', function(e) {
    $('#utility-details-modal').modal('hide');
});

document.getElementById('payment-proceed').addEventListener('click', function(e){
    if ($('#payment-sum-input').val() < 1){
        $('#wrong-sum').show();
    }else{
        $('#wrong-sum').hide();
    }


    if ($('input[name=options]:radio:checked').filter(":checked").val() === undefined){
        $('#option-unchecked-msg').show();
    }else{
        $('#option-unchecked-msg').hide();
    }

    let correct = ($('#payment-sum-input').val() >= 1 && !(!$("input[name='options']:checked").val()));

    if (correct) {
        $('#option-unchecked-msg').hide();
        $('#wrong-sum').hide();
        totalSumToPay = $('#payment-sum-input').val();
        popup();
    }
});

$('#historyTable').on('change', '.checkthis', function(){
    $('#pay').prop('disabled', !$('.checkthis:checked').length);
});

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

$(document).on('click', '.change-value', function(){
    oldValue = $(this).closest('tr').find('td.oldValue').attr('data-value');
});

$('#selectAddress').on('change', function(e){
   setUtilities();
});

$('#utility-details-modal').on('show.bs.modal', function(e){
    utilityId = $(e.relatedTarget).data('id');
    debtId = $(e.relatedTarget).data('debt-id');
    let utilityCounters = getData('/user/utility/' + utilityId + '/counters?addressId=' + $('#selectAddress').val());

    let tbody = $('#modal-table > tbody');
    let options = "";

    utilityCounters.forEach((elem) => {
        options += buildUtilityCounterItem(elem);
    });

    $(tbody).html(options);
});

$('.js-apply').on('click', function(){
    let newCurrentValue = $('#newCurrentValue').val();
    let URL = '/user/counter/' + counterToUpdId + '/value/update';
    let message = 'Value';

    if (newCurrentValue <= 0 || newCurrentValue < oldValue){
        $('#wrong-value').show();
    }else{
        $('#wrong-value').hide();
        ajaxUpdateCounter(counterToUpdId, URL, newCurrentValue, message);
    }
});

$('#paymentSumModal').on('show.bs.modal', function(){
    $('#download-check-text').html(locales.downloadCheck);
    $('#send-check-text').html(locales.sendCheck);
});

$(document).on('show.bs.modal', '.modal', function () {
    var zIndex = 1040 + (10 * $('.modal:visible').length);
    $(this).css('z-index', zIndex);
    setTimeout(function() {
        $('.modal-backdrop').not('.modal-stack').css('z-index', zIndex - 1).addClass('modal-stack');
    }, 0);
});

function ajaxUpdateCounter(counterId, url, value, message){
    $.ajax({
        type: 'POST',
        url: url + '?value=' + value,
        data: null,
        contentType: 'application/json; charset=utf-8',
        success: function (response) {
            notify(locales["success"], locales[response], "success", 3000);
            $('#user-change-counter-value-modal').modal('hide');
            setTimeout(function(){
                window.location.reload();
            }, 4000);
        },
        error: function (error) {
            notify(locales["error"], locales[error.responseJSON], "error", 3000);
            $('#user-change-counter-value-modal').modal('hide');
        },

        timeout: 120000
    });
}

$('#user-change-counter-value-modal').on('show.bs.modal', function(e){
    counterToUpdId = $(e.relatedTarget).attr('data-id');

});

function getData(url) {
    let xhr = new XMLHttpRequest();
    xhr.open('GET', url, false);
    xhr.send();
    if (xhr.status === 200) {
        return JSON.parse(xhr.responseText);
    }
}

function buildUtilityItem(elem) {
    let balance = 0;
    let debt = getData('/user/utility/' + elem.id + '/debt?addressId=' + $('#selectAddress').val());
    balance = -debt.value;
    let str = `<tr class="utilityInfo">
    <td class="utilityId">${elem.name}</td>
    <td class="balance">${balance}</td>
    <td><button type="button" class="btn btn-primary mt-2" data-toggle="modal" data-id="${elem.id}" data-debt-id="${debt.id}"
    data-target="#utility-details-modal" >${locales.details}</button></td>
    `;
    return str;
}

function buildUtilityCounterItem(elem){
    let str = `<tr data-id="${elem.id}">
        <td class="oldValue" data-value="${elem.oldValue}">${elem.oldValue}</td>
        <td>${elem.currentValue}</td>
        <td>
        ${elem.fixed ? '<button type="button" class="btn btn-primary change-value" disabled data-toggle="modal" ' +
        'data-target="#user-change-counter-value-modal" data-id="' + elem.id + '">' + locales.setNewValue + '</button>'  :
        '<button type="button" class="btn btn-primary change-value" data-toggle="modal" ' +
        'data-target="#user-change-counter-value-modal" data-id="' + elem.id + '" >' + locales.setNewValue + '</button>'}
        </td>
    </tr>
    `;
    return str;
}

$(document).ready(
        function first() {
            $('title').html(locales.userPaymentsTitle);
            let addresses = [];

            $.ajax({
                type: 'GET',
                url: '/listById',
                contentType: 'application/json; charset=utf-8',
                success: function (response) {
                    addresses = response;
                    $.each(addresses, function () {
                        let template = $.isNumeric(this.flat.number) ? "{0} {1}/{2}, {3}, {4}" : "{0} {1}{2}, {3}, {4}";
                        $('#selectAddress').append($("<option></option>")
                            .attr("value", this.id)
                            .text(getFullAddressWithTemplate(this, template)));
                    });

                    setUtilities();

                },
                error: function (jqXHR, textStatus, errorThrown) {

                },

                timeout: 120000
            });

        }
        );

function setUtilities(){
    hideFormShowLoader();
    $.ajax({
        type: 'GET',
        url: '/user/payments?id=' + $('#selectAddress').val(),
        success: function (response) {
            let tbody = $('#historyTable > tbody');
            let options = "";

            if (response.length != 0) {
                response.forEach((elem) => {
                    options += buildUtilityItem(elem);
                });
            }

            $(tbody).html(options);
            hideLoaderShowForm();
        },
        error: function (jqXHR, textStatus, errorThrown) {
            hideLoaderShowForm();
        },

        timeout: 120000
    });
}

function popup(){
    var rows = [];

    $('#historyTable tr').filter(':has(:checkbox.checkthis:checked)').each(function(){
        rows[rows.length] = $(this);
    });

    // Open Checkout with further options:
    handler.open({
        name: 'EasyPay',
        description: 'Some test payment',
        zipCode: true,
        currency: 'usd'
    });


}

function payAndSendCheck(){
    $.ajax({
        url: '/user/debt/change?sum=' + totalSumToPay + '&addressId=' + $('#selectAddress').val() + '&utilityId=' + utilityId,
        type: 'POST',
        contentType: "application/json",
        success: function(response){
            notify(locales["success"], locales[response], 'success', 3000);
            hideLoaderShowForm();
            setTimeout(function(){
                window.location.reload();
            }, 4000);
        },
        error: function (error) {
            hideLoaderShowForm();
            notify(locales["error"] , locales[error.responseJSON], 'error', 3000);
        },

        timeout: 120000
    });
}

function payAndDownloadCheck(){
    $.ajax({
        url: '/user/debt/change/check?sum=' + totalSumToPay + '&addressId=' + $('#selectAddress').val() + '&utilityId=' + utilityId + '',
        type: 'POST',
        contentType: "application/json",

        success: function(response){
            hideLoaderShowForm();
            $.ajax({
                type: 'GET',
                url: '/user/payments/history/check?fileId=' + response,
                success: function (response) {
                    window.location.href = response;
                },
                error: function (jqXHR, textStatus, errorThrown) {

                },

                timeout: 120000
            });
        },
        error: function (error) {
            hideLoaderShowForm();
            notify(locales["error"], locales[error.responseJSON], 'error', 3000);
        },

        timeout: 120000
    });
}

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