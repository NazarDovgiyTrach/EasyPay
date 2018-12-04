let CHART_BACKGROUND_COLOR = 'rgba(166, 255, 254, 0.3)';
let CHART_POINT_COLOR = 'rgba(0, 0, 0, 0.5)';
let chart;

function createChart(config) {
    let ctx = $("#canvas").get(0).getContext("2d");
    chart = new Chart(ctx, config);
    window.myLine = chart;
}

$('#tab2').click(function () {
    let startDate = new Date().getFullYear() + '-01-01';
    let targetDate = getCurrentDate();
    let startUrl = '/manager/utility/price/chart?startDate=' + startDate + '&targetDate=' + targetDate;

    getPrices(createChart, startUrl);
    dateChoosingSetup();
});

function getChartConfig(dates, prices) {
    return {
        type: 'line',
        data: {
            labels: dates,
            datasets: [{
                label: "Price",
                data: prices,
            }]
        },
        options: {
            responsive: true,
            tooltips: {
                mode: 'label',
                callbacks: {
                }
            },
            hover: {
                mode: 'dataset'
            },
            scales: {
                xAxes: [{
                    display: true,
                    scaleLabel: {
                        show: true,
                        labelString: 'Month'
                    }
                }],
                yAxes: [{
                    display: true,
                    scaleLabel: {
                        show: true,
                        labelString: 'Value'
                    },
                    ticks: {
                        suggestedMin: 0,
                        suggestedMax: Math.max.apply(Math, prices) + 1,
                    }
                }]
            }
        }
    };
}

function setChartStyle(config) {
    $.each(config.data.datasets, function(i, dataset) {
        dataset.backgroundColor = CHART_BACKGROUND_COLOR;
        dataset.pointBorderColor = CHART_POINT_COLOR;
        dataset.pointBorderWidth = 1;
    });
}

function dateChoosingSetup() {
    let controllerUrl = '/manager/utility/price/chart';
    let startDateInput = $('#start_date');
    let targetDateInput = $('#target_date');

    $('.input-daterange input').each(function() {
        $(this).datepicker({
            format: "yyyy-mm-dd",
            weekStart: 1,
            endDate: new Date(),
            autoclose: true
        });
    });

    $('#chart_date_form .input-group.date').datepicker({
        viewMode: 'years',
        minViewMode: 'years',
        format: ' yyyy',
        endDate: new Date(),
        autoclose: true
    });

    startDateInput.on('changeDate', function () {
        let targetDate = targetDateInput.val();

        if (targetDate === '')
            return;

        let startDate = startDateInput.val();
        if (!/^\d{4}-\d?\d-\d?\d$/.test(startDate)) {
            $('#price_history_info').html(locales['incorrectStartDate']);
            return;
        }

        getPrices(createChart, controllerUrl + '?startDate=' + startDate + '&targetDate=' + targetDate);
    });

    targetDateInput.on('changeDate', function () {
        let startDate = startDateInput.val();

        if (startDate === '')
            return;

        let targetDate = targetDateInput.val();
        if (!/^\d{4}-\d?\d-\d?\d$/.test(targetDate)) {
            $('#price_history_info').html(locales['incorrectTargetDate']);
            return;
        }

        getPrices(createChart, controllerUrl + '?startDate=' + startDate + '&targetDate=' + targetDate);
    });
}

function getPrices(callback, url) {
    $('#no_price_history').html('');
    $.ajax({
        url: url,
        type: 'GET',
        dataType: 'json',

        success: function (data) {
            if ($.isEmptyObject(data.prices)) {
                if (typeof chart !== "undefined")
                    chart.destroy();
                $('#no_price_history').html(locales['nothingToShow']);
            } else {
                let dates = [];
                let prices = [];

                $.map(data.prices, function (price, date) {
                    dates.push(date);
                    prices.push(price);
                });

                let config = getChartConfig(dates, prices);
                setChartStyle(config);
                callback(config);
            }
        },
        error: function() {
            PNotify.removeAll();
            new PNotify({
                title: locales['error'],
                text: locales['somethingWentWrong'],
                type: "error",
                styling: 'bootstrap3',
                delay: 2000
            });
        }
    });
}