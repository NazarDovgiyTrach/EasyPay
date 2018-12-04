let counterToUpdId;
let oldValue;
let isFixed;
let isActive;
let addresses = [];

$(document).ready(
    function setData() {
        $('.combobox').combobox();
        $.ajax({
            type: 'GET',
            url: '/inspector/addresses',
            contentType: 'application/json; charset=utf-8',
            success: function (response) {
                addresses = response;

                $.each(addresses, function() {
                    let template = $.isNumeric(this.flat.number) ? "{0} {1}/{2}, {3}, {4}" : "{0} {1}{2}, {3}, {4}";
                    $('#selectAddress').append($("<option></option>")
                        .attr("value", this.id)
                        .text(getFullAddressWithTemplate(this, template)));
                });

                let select = $('#selectAddress');
                select.data('combobox').refresh();
                select.data('combobox').clearTarget();
                select.data('combobox').clearElement();

                $('title').html(locales.checkCountersTitle);

            },
            error: function (jqXHR, textStatus, errorThrown) {

            },

            timeout: 120000
        });



    });

$(document).on('click', '.change-status', function(){
    let data = $(this).data('id');
    let status = data[0];
    let counterId = data[1];
    let URL = '/inspector/counter/' + counterId + '/status/update?value=' + status;

    ajaxUpdateCounter(URL);
});

$(document).on('click', '.change-value', function(){
    oldValue = $(this).closest('tr').find('td.oldValue').attr('data-value');
    isFixed = $(this).closest('tr').find('td.is-fixed').attr('data-value');
});

$(document).on('click', '.change-type', function(){
    let data = $(this).data('id');
    let type = data[0];
    let counterId = data[1];
    let URL = '/inspector/counter/' + counterId + '/type/update?value=' + type;

    ajaxUpdateCounter(URL);
});

$(document).on('click', '.init-with-values', function(){
    let currentValue = $(this).closest('tr').find('td.counter-value').attr('data-value');
    let counterId = $(this).data('id');
    let URL = '/inspector/counter/' + counterId + '/init';

    isActive = $(this).closest('tr').find('td.is-active').attr('data-value');

    if (!isActive){
        notify(locales["error"], locales["responseUnactiveCounterNotInitializable"], "error", 3000);
    }else if (currentValue > 0){
        notify(locales["error"], locales["responseCounterAlreadyInitialized"], "error", 3000);
    }else{
        ajaxUpdateCounter(URL);
    }
});

$('.js-apply').on('click', function(){
    let newCurrentValue = $('#newCurrentValue').val();
    let URL = '/inspector/counter/' + counterToUpdId + '/value/update?value=' + newCurrentValue;

    if (newCurrentValue <= 0 || newCurrentValue < oldValue){
        $('#wrong-value').show();
    }else if (isFixed){
        notify(locales["error"], locales["responseFixedCounterImmutable"], "error", 3000);
    } else{
        $('#wrong-value').hide();
        ajaxUpdateCounter(URL);
    }
});

$('#changeValuesModal').on('show.bs.modal', function(e){
   counterToUpdId = $(e.relatedTarget).attr('data-id');
});

$('#selectAddress').on('change', function(e){
   let addressId = $("option:selected", this).val();
   if (addressId !== undefined) {
       $('#countersTable > tbody').html("");
       ajaxGetUnfixedCountersByAddressId(addressId);
   }
});


function getAddressId(list, streetId, houseId, flatId, callback){
    $.each(list, function(index, element){
        if (element.street.id == streetId && element.house.id == houseId && element.flat.id == flatId) {
            callback(this.id);
        }
    });
}

function ajaxGetUnfixedCountersByAddressId(addressId){
    $.ajax({
        type: 'GET',
        url: '/inspector/address/' + addressId + '/counters',
        success: function (response) {
            if (response != null)
                setCounters(response);
        },
        error: function (jqXHR, textStatus, errorThrown) {

        },

        timeout: 120000
    });
}

function ajaxUpdateCounter(url){
    $.ajax({
        type: 'POST',
        url: url,
        data: null,
        contentType: 'application/json; charset=utf-8',
        success: function (response) {
            notify(locales["success"], locales["responseCounterUpdated"], "success", 3000);
            $('#changeValuesModal').modal('hide');
            setTimeout(function(){
                window.location.reload();
            }, 4000);
        },
        error: function (error) {
            notify(locales["error"], locales[error.responseJSON], "error", 3000);
            $('#changeValuesModal').modal('hide');
        },

        timeout: 120000
    });
}

function setCounters(data){
    let row;
    let utilityName = data.utilityName;

    $.each(data.counters, function() {
        row +=
            '<tr data-id="' + utilityName + '"' + '>' +
            '<td>' + utilityName + '</td>' +
            '<td class="oldValue" data-value="' + this.oldValue + '">' + this.oldValue + '</td>' +
            '<td class="counter-value" data-value="' + this.currentValue + '">' + this.currentValue + '</td>' +
            '<td class="is-active" data-value="' + this.active + '">' + (this.active ? '<span class="fa fa-check counter-status"></span>'
            : '<span class="fa fa-times counter-status"></span>') + '</td>' +
            '<td class="is-fixed" data-value="' + this.fixed + '">' + (this.fixed ? '<span class="fa fa-check counter-type"></span>'
            : '<span class="fa fa-times counter-type"></span>') + '</td>' +
            '<td class="is-fixed" data-value="' + this.fixed + '">' + '<button type="button" class="change-status btn btn-primary" data-id="[' + !this.active + ',' + this.id + ']"'
            + '>' + (this.active ? locales.deactivate : locales.activate) + '</button>' +
            '<button type="button" class="change-type btn btn-primary" data-id="[' + !this.fixed + ',' + this.id + ']"'
            + '>' + (this.fixed ? locales.setUnfixed : locales.setFixed) + '</button>' +
            (this.oldValue == 0 && this.currentValue == 0 && this.active ? '<button type="button" class="init-with-values btn btn-primary" data-id="' + this.id + '">' + locales.initCounter + '</button>'
                : '<button type="button" class="init-with-values btn btn-primary" disabled data-id="' + this.id + '">' + locales.initCounter + '</button>')+

            (this.fixed ?
                '<button type="button" class="btn btn-primary change-value" disabled data-toggle="modal" ' +
                'data-target="#changeValuesModal" data-id="' + this.id + '">' + locales.setNewValue + '</button>' :
                '<button type="button" class="btn btn-primary change-value" data-toggle="modal" ' +
                'data-target="#changeValuesModal" data-id="' + this.id + '">' + locales.setNewValue + '</button>') +

            '</td>' +
            '</tr>';

        $('#countersTable tbody').append(row);
    });
}

let notify = function showNotify(title, text, type, delay){
    new PNotify({
        title: title,
        text: text,
        type: type,
        styling: 'bootstrap3',
        delay: delay
    });
};