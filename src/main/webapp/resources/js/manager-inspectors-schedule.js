$(function () {
    $('.combobox').combobox();
    setInspectorName(getInspectorIdByUrl());
    setAddressToForms();
    initDatepickers();
    initCalendar();
    setCalendarEvents();
});

$(document).ajaxComplete(function () {
    $("#datetimepicker").data("DateTimePicker").date(moment());
});

$(document).on('click', '.js-add-apply', function () {
    var modal = $(this).closest('.modal'),
        form = modal.find("form");

    $.post({
        url: "/manager/schedule/item/inspector/{0}".format(getInspectorIdByUrl()),
        data: JSON.stringify({
            address: {id: form.children('select#address-add').val()},
            eventDate: form.children('input[name=date]').val(),
            repeat: form.children('input[name=repeat]').prop("checked")
        }),
        contentType: "application/json; charset=utf-8",
        complete: function (data, status) {
            if (data.status !== 400) {
                setCalendarEvents();
                modal.modal('hide');
                form[0].reset();
                reinitCheckbox();
                showNotify(status, data.responseJSON);
            } else {
                showErrors(data.responseJSON);
            }
        }
    });

});

$(document).on('click', '.js-remove-apply', function () {
    var modal = $(this).closest('.modal');

    $.ajax({
        url: "/manager/schedule/item/{0}".format(modal.attr("data-id")),
        type: "DELETE",
        contentType: "application/json; charset=utf-8",
        complete: function (data, status) {
            setCalendarEvents();
            modal.modal('hide');
            showNotify(status, data.responseJSON);
        }
    });
});

$(document).on('click', '.js-edit-apply', function () {
    var modal = $(this).closest('.modal'),
        form = modal.find("form");

    $.ajax({
        url: "/manager/schedule/item/{0}".format(modal.attr("data-id")),
        type: 'PUT',
        data: JSON.stringify({
            address: {id: form.children('select#address-edit').val()},
            eventDate: form.children('input[name=date]').val(),
            repeat: form.children('input[name=repeat]').prop("checked")
        }),
        contentType: "application/json; charset=utf-8",
        complete: function (data, status) {
            if (data.status !== 400) {
                setCalendarEvents();
                modal.modal('hide');
                form[0].reset();
                showNotify(status, data.responseJSON);
            } else {
                showErrors(data.responseJSON);
            }
        }
    });

});

$(document).on('click', '[data-target="#map-modal"]', function () {
    var date = $(this).attr("data-date");
    $('#map-modal .js-date').text(date);

    var array = $('#manager-calendar').fullCalendar('clientEvents', function (events) {
        return (moment(events.start).format('YYYY-MM-DD') === moment(date).format('YYYY-MM-DD'));
    });

    setDirections(array);
});

function setAddressToForms() {
    $.get({
        url: '/manager/schedule/inspectors/addresses/get/',
        success: function (data) {
            $.each(data, function (index, element) {
                var address = '<option value="{0}">{1}</option>',
                    template = $.isNumeric(element.flat.number) ? "{0} {1}/{2}, {3}, {4}" : "{0} {1}{2}, {3}, {4}";
                $('select.address-add').append(address.format(element.id, getFullAddressWithTemplate(element, template)));
            });
            $('select#address-add').data('combobox').refresh();
            $('select#address-edit').data('combobox').refresh();
        }
    });
}

function setInspectorName(id) {
    $.get({
        url: '/getUserById?id=' + id,
        success: function (data) {
            $(".js-name-inspector").html("{0} {1}".format(data.name, data.surname));
        }
    });
}

function initDatepickers() {
    $('.datetimepicker').each(function () {
        $(this).datetimepicker({
            locale: moment.locale(locales["scheduleLocale"]),
            format: 'YYYY-MM-DD',
            minDate: moment().millisecond(0).second(0).minute(0).hour(0),
            maxDate: moment().add(1, 'months').endOf('month'),
            defaultDate: moment()
        }).on("dp.change", function (e) {
            if ($(this).val().length === 0) {
                $(this).data("DateTimePicker").date(moment());
            }
        });
    });
}

function initCalendar() {
    if (typeof($.fn.fullCalendar) === 'undefined') {
        return;
    }

    $('#manager-calendar').fullCalendar({
        locale: locales["scheduleLocale"],
        defaultView: 'month',
        validRange: {
            start: new Date(new Date().getFullYear(), new Date().getMonth(), 1),
            end: new Date(new Date().getFullYear(), new Date().getMonth() + 2, 1)
        },
        customButtons: {
            addScheduleItem: {
                text: locales["scheduleLocale"] === "uk" ? "Додати елемент розкладу" : "Add schedule item",
                click: function () {
                    hideErrors();
                    var select = $('select#address-add').data('combobox');
                    select.clearTarget();
                    select.clearElement();
                    $("#add-modal").modal("show");
                }
            }
        },
        header: {
            left: 'prev,next today',
            center: 'title',
            right: 'addScheduleItem'
        },
        eventLimit: true,
        fixedWeekCount: false,
        eventClick: function (calEvent, jsEvent, view) {
            jsEvent.preventDefault();
            hideErrors();

            var form = $(calEvent.toogle).find("form");

            if (new Date(calEvent.eventDate) < new Date()) {
                form.children('input.datetimepicker').data("DateTimePicker").minDate(new Date(calEvent.eventDate));
            }

            form.children('input.datetimepicker').data("DateTimePicker").date(new Date(calEvent.eventDate));
            form.children('select#address-edit').children('option[value=' + calEvent.address.id + ']').prop("selected", true);
            form.children('input[name="repeat"]').prop("checked", calEvent.repeat);
            reinitCheckbox();

            $('select#address-edit').data('combobox').refresh();

            $(calEvent.toogle).attr("data-id", calEvent.id);
            $(calEvent.toogle).modal('show');
        },
        eventRender: function (event, element, view) {
            if (event.repeat)
                element.find('.fc-content').prepend('<i class="fa fa-repeat"></i>');
        },
        eventAfterRender: function (event, element, view) {
            var removeBtm = '<button data-toggle="modal" data-target="#remove-modal" class="btn btn-sm btn-transparent" type="button" data-id="{0}">' +
                '<i class="fa fa-trash-o"></i>' +
                '</button>';
            element.before(removeBtm.format(event.id));
        },
        eventAfterAllRender: function (date) {
            $(".click").remove();
            $.each($('#manager-calendar').fullCalendar('clientEvents'), function (index, element) {
                var date = moment(new Date(element.eventDate)).format('YYYY-MM-DD').toString();
                var parrent = $('td[data-date="' + date + '"]');
                if (parrent.find(".click").length < 1) {
                    parrent.append('<a data-toggle="modal" data-target="#map-modal" class="click" data-date="'
                        + date + '"><i class="fa fa-map-marker"></i> ' + locales["scheduleRoute"] + '</a>');
                }
            });
        }
    });
}

function setCalendarEvents() {
    $.get({
        url: '/manager/schedule/item/list/inspector/{0}'.format(getInspectorIdByUrl()),
        success: function (data) {
            $("#manager-calendar").fullCalendar('removeEvents');
            $.each(data, function (index, element) {
                var template = $.isNumeric(element.address.flat.number) ? "{0} {1}/{2}\n{3},\n{4}" : "{0} {1}{2}\n{3},\n{4}";

                $('#manager-calendar').fullCalendar('renderEvent', {
                    id: element.id,
                    repeat: element.repeat,
                    date: element.date,
                    address: element.address,
                    eventDate: element.eventDate,
                    toogle: '#edit-modal',
                    title: getFullAddressWithTemplate(element.address, template),
                    start: new Date(element.eventDate),
                    allDay: true,
                    color: '#1ABB9C',
                    url: "#",
                }, true);
            });
        }
    });
}
