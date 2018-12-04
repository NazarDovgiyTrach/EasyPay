$(document).on('click', 'button[data-toggle="modal"]', function () {
    var modal = $($(this).attr("data-target")),
        id = $(this).attr("data-id");

    modal.attr("data-id", id);
    hideErrors();
});

function getInspectorIdByUrl() {
    var url = $(location).attr('pathname');
    var urlParts = url.split("/");
    return urlParts[4];
}

function showNotify(type, message) {
    new PNotify({
        title: locales["pnotify" + type.capitalize()],
        text: message,
        type: type.toLowerCase(),
        styling: 'bootstrap3',
        delay: 1000
    });
}

function getFullAddress(address) {
    var template = "{0}, {1}, {2} {3}{4}";
    var flat = (address.flat.number.length > 0) ? "/" + address.flat.number : "";
    return template.format(address.region.name, address.city.name, address.street.name, address.house.number, flat);
}

function getFullAddressWithTemplate(address, template) {
    /*var result = null,
        fullAddress = "{0}, {1}, {2} {3}".format(
            address.region.name,
            address.city.name,
            address.street.name,
            parseInt(address.house.number)
        ),
        house = locales["scheduleLocale"] === 'en' ? transliterate(address.house.number).toUpperCase() : address.house.number.toUpperCase();

    $.get({
        url: "https://maps.googleapis.com/maps/api/geocode/json?address={0}&language={1}".format(encodeURIComponent(fullAddress), locales["scheduleLocale"]),
        async: false,
        success: function (data) {
            var addr = data.results[0].formatted_address.split(",");
            result = template.format(addr[0], house, address.flat.number, addr[2], addr[3]);
        }
    });

    return result;*/
    var flat = (address.flat.number.length > 0) ? address.flat.number : "";
    return template.format(
        address.street.name,
        address.house.number,
        flat,
        address.city.name,
        address.region.name);
}

function reinitCheckbox() {
    if ($(".js-switch")[0]) {
        var elems = Array.prototype.slice.call(document.querySelectorAll('.js-switch'));
        $('.switchery').remove();
        elems.forEach(function (html) {
            var switchery = new Switchery(html, {
                color: '#26B99A'
            });
        });
    }
}

function showErrors(errors) {
    errors = $.parseJSON(errors);

    if (errors.hasOwnProperty('eventDate')) {
        $("ul.date-error").removeClass("hide");
        $("li.date-error").text(errors["eventDate"]);
        $("input.date-error").addClass("parsley-error");
    } else {
        $("ul.date-error").addClass("hide");
        $("input.date-error").removeClass("parsley-error");
    }

    if (errors.hasOwnProperty('address.id')) {
        $("ul.address-error").removeClass("hide");
        $("li.address-error").text(errors["address.id"]);
        $("select.address-error").addClass("parsley-error");
    } else {
        $("ul.address-error").addClass("hide");
        $("select.address-error").removeClass("parsley-error");
    }

    if (errors.hasOwnProperty('isRepeat')) {
        $("ul.repeat-error").removeClass("hide");
        $("li.repeat-error").text(errors["isRepeat"]);
        $("input.repeat-error").addClass("parsley-error");
    } else {
        $("ul.repeat-error").addClass("hide");
        $("input.repeat-error").removeClass("parsley-error");
    }
}

function hideErrors() {
    $("ul.date-error").addClass("hide");
    $("input.date-error").removeClass("parsley-error");
    $("ul.address-error").addClass("hide");
    $("select.address-error").removeClass("parsley-error");
    $("ul.repeat-error").addClass("hide");
    $("input.repeat-error").removeClass("parsley-error");
}

String.prototype.format = String.prototype.f = function () {
    var s = this,
        i = arguments.length;

    while (i--) {
        s = s.replace(new RegExp('\\{' + i + '\\}', 'gm'), arguments[i]);
    }

    return s;
};

String.prototype.capitalize = function () {
    return this.charAt(0).toUpperCase() + this.slice(1)
};

var transliterate = function (text) {
    return text
        .replace(/\u0401/g, 'YO')
        .replace(/\u0419/g, 'I')
        .replace(/\u0426/g, 'TS')
        .replace(/\u0423/g, 'U')
        .replace(/\u041A/g, 'K')
        .replace(/\u0415/g, 'E')
        .replace(/\u041D/g, 'N')
        .replace(/\u0413/g, 'G')
        .replace(/\u0428/g, 'SH')
        .replace(/\u0429/g, 'SCH')
        .replace(/\u0417/g, 'Z')
        .replace(/\u0425/g, 'H')
        .replace(/\u042A/g, '')
        .replace(/\u0451/g, 'yo')
        .replace(/\u0439/g, 'i')
        .replace(/\u0446/g, 'ts')
        .replace(/\u0443/g, 'u')
        .replace(/\u043A/g, 'k')
        .replace(/\u0435/g, 'e')
        .replace(/\u043D/g, 'n')
        .replace(/\u0433/g, 'g')
        .replace(/\u0448/g, 'sh')
        .replace(/\u0449/g, 'sch')
        .replace(/\u0437/g, 'z')
        .replace(/\u0445/g, 'h')
        .replace(/\u044A/g, "'")
        .replace(/\u0424/g, 'F')
        .replace(/\u042B/g, 'I')
        .replace(/\u0412/g, 'V')
        .replace(/\u0410/g, 'a')
        .replace(/\u041F/g, 'P')
        .replace(/\u0420/g, 'R')
        .replace(/\u041E/g, 'O')
        .replace(/\u041B/g, 'L')
        .replace(/\u0414/g, 'D')
        .replace(/\u0416/g, 'ZH')
        .replace(/\u042D/g, 'E')
        .replace(/\u0444/g, 'f')
        .replace(/\u044B/g, 'i')
        .replace(/\u0432/g, 'v')
        .replace(/\u0430/g, 'a')
        .replace(/\u043F/g, 'p')
        .replace(/\u0440/g, 'r')
        .replace(/\u043E/g, 'o')
        .replace(/\u043B/g, 'l')
        .replace(/\u0434/g, 'd')
        .replace(/\u0436/g, 'zh')
        .replace(/\u044D/g, 'e')
        .replace(/\u042F/g, 'Ya')
        .replace(/\u0427/g, 'CH')
        .replace(/\u0421/g, 'S')
        .replace(/\u041C/g, 'M')
        .replace(/\u0418/g, 'I')
        .replace(/\u0422/g, 'T')
        .replace(/\u042C/g, "'")
        .replace(/\u0411/g, 'B')
        .replace(/\u042E/g, 'YU')
        .replace(/\u044F/g, 'ya')
        .replace(/\u0447/g, 'ch')
        .replace(/\u0441/g, 's')
        .replace(/\u043C/g, 'm')
        .replace(/\u0438/g, 'i')
        .replace(/\u0442/g, 't')
        .replace(/\u044C/g, "'")
        .replace(/\u0431/g, 'b')
        .replace(/\u044E/g, 'yu');
};