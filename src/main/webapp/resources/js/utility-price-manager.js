let PRICE_SIGN = '₴';
let months = [locales['month.january'], locales['month.february'], locales['month.march'], locales['month.april'],
    locales['month.may'], locales['month.june'], locales['month.july'], locales['month.august'],
    locales['month.september'], locales['month.october'], locales['month.november'], locales['month.december']];

let BAD_REQUEST_CODE = 400;
let METHOD_NOT_ALLOWED = 405;

$( document ).ready(function() {
    let ANIMATION_TYPE = 'slow';
    let priceFormBtn = $('#price_form_btn');
    let futurePriceFormBtn = $('#future_price_form_btn');
	let priceFormDiv = $('#price_div');
	let futurePriceFormDiv = $('#future_price_div');

	getDataForCurrentValues(function (currentPrice) {
	    if (currentPrice.date == null) {
            currentPrice.utilityPriceDTO.active = true;
            putCurrentPrice(currentPrice, "/manager/utility/price/update");
        } else {
            putCurrentPrice(currentPrice, "/manager/utility/price/add");
        }

        getDataForFutureValues(currentPrice, function (data, currentPrice) {
            putFuturePrice(data, currentPrice); // using when newPrice exist in DB
        }, function (currentPrice) {
            putFuturePrice(null, currentPrice); // using when newPrice doesn`t exist DB
        });
    });

    function putCurrentPrice(currentPrice, url) {
        $('#price_form').on('submit', function (e) {
            e.preventDefault();

            currentPrice.price = $('#new_price_value').val();
            currentPrice.date = getCurrentDate();

            $.ajax({
                url: url,
                type: 'PUT',
                data: JSON.stringify(currentPrice),
                contentType: "application/json",

                success: function () {
                    refreshPage();
                    priceFormDiv.hide(ANIMATION_TYPE);
                    showSuccessNotify(locales['currentPriceUpdated']);
                },
                error: function(error) {
                    priceFormDiv.hide();
                    priceFormBtn.prop("disabled", false);
                    showErrorNotify(getErrorText(error));
                }
            });
        });
    }

    function putFuturePrice (data, currentPrice) {
        $('#future_price_form').on('submit', function (e) {
            e.preventDefault();

            if (data != null) {
                data.newPrice = $('#future_price_value').val();
                data.activationDate = $('#future_price_date').val();
            } else {
                data = {
                    currentPriceId: currentPrice.currentPriceId,
                    activationDate: $('#future_price_date').val(),
                    newPrice: $('#future_price_value').val()
                };
            }

            $.ajax({
                url: '/manager/utility/price/new/update',
                type: 'PUT',
                data: JSON.stringify(data),
                contentType: "application/json",

                success: function () {
                    refreshPage();
                    futurePriceFormDiv.hide(ANIMATION_TYPE);
                    showSuccessNotify(locales['futurePriceUpdated']);
                },
                error: function(error) {
                    futurePriceFormDiv.hide();
                    futurePriceFormBtn.prop("disabled", false);
                    showErrorNotify(getErrorText(error));
                }
            });
        });
    }

    $('#future_price_form .input-group.date').datepicker({
        format: "yyyy-mm-dd",
        weekStart: 1,
        startDate: '+1d',
        autoclose: true
    });

    priceFormBtn.click(function(){
        priceFormBtn.prop("disabled", true);
        futurePriceFormBtn.prop("disabled", false);
        futurePriceFormDiv.hide(ANIMATION_TYPE);
        priceFormDiv.show(ANIMATION_TYPE);
    });

    futurePriceFormBtn.click(function() {
        futurePriceFormBtn.prop("disabled", true);
        priceFormBtn.prop("disabled", false);
        priceFormDiv.hide(ANIMATION_TYPE);
        futurePriceFormDiv.show(ANIMATION_TYPE);
    });
});

function getDataForCurrentValues(callback) {
    $.ajax({
        url: '/manager/utility/price/get',
        type: 'GET',
        dataType: 'json',
        success: function (data) {
            showFormButtons();
            let utilityAddress = data.priceAddressDTO;

            $('#service_name_and_address').html(data.utilityPriceDTO.utilityName + ' ( ' +
                utilityAddress.cityName + ', ' +
                utilityAddress.streetName  + ' ' +
                utilityAddress.houseNumber + ' )');

            $('#tabs').show();

            if (data.date == null) {
                $('#utility_info').html(locales['utilityDisabledWarning']);
                $('#service_price').html(locales['utilityDisabledCurrentPrice']);
                $('#service_last_activation_date').html(locales['utilityDisabledCurrentDate']);
            } else {
                $('#utility_info').html('');
                $('#service_price').html(locales['currentPrice'] + PRICE_SIGN + data.price);
                $('#service_last_activation_date').html(locales['activationDate'] + getFormattedDate(data.date));
            }
            callback(data);
        },
        error: function () {
            $('#service_name_and_address').html(locales['noUtility']);

        }
    });
}

function getDataForFutureValues(currentPrice, callbackSuccess, callbackError) {
    $.ajax({
        url: '/manager/utility/price/new/get',
        type: 'GET',
        dataType: 'json',
        success: function (data) {
            $('#future_price').html(locales['futurePrice'] + PRICE_SIGN + data.newPrice);
            $('#activation_date').html(locales['nextActivationDate'] + getFormattedDate(data.activationDate));
            callbackSuccess(data, currentPrice);
        },
        error: function () {
            $('#future_price').html(locales['utilityDisabledFuturePrice']);
            $('#activation_date').html(locales['utilityDisabledFutureDate']);
            callbackError(currentPrice);
        }
    });
}

function showFormButtons() {
    $('#price_form_btn').show();
    $('#future_price_form_btn').show();
}

function getFormattedDate(date) {
    let year = date[0];
    let monthNumber = date[1] - 1;
    let day = date[2];

    return day + ' ' + months[monthNumber].toUpperCase() + ' ' + year;
}

function getCurrentDate() {
    let today = new Date();

    let dd = today.getDate();
    let mm = today.getMonth() + 1; //January is 0!
    let yyyy = today.getFullYear();

    if(dd < 10)
        dd = '0' + dd;

    if(mm < 10)
        mm = '0' + mm;

    return yyyy + '-' + mm + '-' + dd;
}

function showSuccessNotify(message) {
        PNotify.removeAll();
        new PNotify({
            title: locales['success'],
            text: message,
            type: 'success',
            styling: 'bootstrap3',
            delay: 2000
        });
}

function showErrorNotify(message) {
    PNotify.removeAll();
    new PNotify({
        title: locales['error'],
        text: message,
        type: 'error',
        styling: 'bootstrap3',
        delay: 2000
    });
}

function getErrorText(error) {
    if (error.status === BAD_REQUEST_CODE || error.status === METHOD_NOT_ALLOWED)
        return locales['enterCorrectData'];
    return error.responseText.replace(/[(\[?")("\]?)]/gm, '').replace(',', '\n');
}

function refreshPage() {
    setTimeout(function(){// wait for 1 sec
        location.reload();
    }, 1000);
}

