$(function () {
    initCalendar();
    setCalendarEvents();
});

$(document).ajaxComplete(function () {
    $('.selectpicker').selectpicker('refresh');
});

$(document).on('change', '#status', function () {
    if ($(this).val() === "DONE") {
        $('button[data-id="status"]').removeClass("btn-danger").addClass("btn-success");
    } else {
        $('button[data-id="status"]').removeClass("btn-success").addClass("btn-danger");
    }
});

$(document).on('click', '.js-apply', function () {
    var modal = $(this).closest('.modal'),
        form = modal.find("form");

    $.post({
        url: "/scheduleHistory/schedule/item/{0}".format(modal.attr("data-id")),
        data: JSON.stringify({
            submitDate: new Date(),
            status: form.find('select[name=status]').val(),
            comment: stripHTML(form.children('textarea[name=comment]').val())
        }),
        contentType: "application/json; charset=utf-8",
        complete: function (data, status) {
            modal.modal('hide');
            form[0].reset();
            reinitCheckbox();
            showNotify(status, data.responseJSON);
        }
    }).done(function () {
        setCalendarEvents();
    });
});

$(document).on('click', '[data-target="#map-modal"]', function () {
    var date = $(this).attr("data-date");
    $('#map-modal .js-date').text(date);

    var array = $('#inspector-calendar').fullCalendar('clientEvents', function (events) {
        return (moment(events.start).format('YYYY-MM-DD') === moment(date).format('YYYY-MM-DD'));
    });

    setDirections(array);
});

function initCalendar() {
    if (typeof($.fn.fullCalendar) === 'undefined') {
        return;
    }

    $('#inspector-calendar').fullCalendar({
        locale: locales["scheduleLocale"],
        validRange: {
            start: new Date(new Date().getFullYear(), new Date().getMonth(), 1),
            end: new Date(new Date().getFullYear(), new Date().getMonth() + 1, 1)
        },
        header: {
            left: 'title',
            center: '',
            right: ''
        },
        eventLimit: true,
        fixedWeekCount: false,
        eventClick: function (calEvent, jsEvent, view) {
            jsEvent.preventDefault();
            $(calEvent.toogle).attr("data-id", calEvent.id);
            $(calEvent.toogle).modal('show');
        },
        eventRender: function (event, element, view) {
            if (event.repeat)
                element.find('.fc-content').prepend('<i class="fa fa-repeat"></i>');
        },
        eventAfterAllRender: function (date) {
            $(".click").remove();
            $.each($('#inspector-calendar').fullCalendar('clientEvents'), function (index, element) {
                var date = moment(new Date(element.eventDate)).format('YYYY-MM-DD').toString();
                var parrent = $('td[data-date="' + date + '"]');
                if (parrent.find(".click").length < 1)
                    parrent.append('<a data-toggle="modal" data-target="#map-modal" class="click" data-date="'
                        + date + '"><i class="fa fa-map-marker"></i> ' + locales["scheduleRoute"] + '</a>');
            });
        }
    });
}

function setCalendarEvents() {
    $.get({
        url: '/inspector/schedule/item/list',
        success: function (data) {
            $("#inspector-calendar").fullCalendar('removeEvents');
            $.each(data, function (index, element) {
                var template = $.isNumeric(element.address.flat.number) ? "{0} {1}/{2}\n{3},\n{4}" : "{0} {1}{2}\n{3},\n{4}";

                $('#inspector-calendar').fullCalendar('renderEvent', {
                    id: element.id,
                    repeat: element.repeat,
                    toogle: '#status_modal',
                    address: element.address,
                    eventDate: element.eventDate,
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

function stripHTML(dirtyString) {
    var container = document.createElement('div');
    var text = document.createTextNode(dirtyString);
    container.appendChild(text);
    return container.innerHTML; // innerHTML will be a xss safe string
}