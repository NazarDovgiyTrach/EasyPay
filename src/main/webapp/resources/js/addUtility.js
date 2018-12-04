document.getElementById('update_button').addEventListener('click', changeManager);
document.getElementById('add_image_button').addEventListener('click', submit);
document.getElementById('update_name_button').addEventListener('click', changeLegalName);
document.getElementById('add_utility_button').addEventListener('click', setManagersOption);
document.getElementById('submit').addEventListener('click', sendData);
document.getElementById('subb').addEventListener('click', createUtility);

let utilityId;
const croppedWidth = 100;
const croppedHeight = 100;
let imageBlob = null;
let cropper;
let image;
let locales = getData("/getMessages");
let phone = '';
let website = '';
(function () {
    createLocalesFilds();
    setManagersOption();
    setPagination();
    changeManagerOption();

}());

function createLocalesFilds() {
    document.getElementById("dropdown-menu-logOut").innerHTML = `<i class="fa fa-sign-out pull-right"></i><span>${locales.logOut}</span>`;

    let data = document.querySelectorAll('[data-locale-item]');
    data.forEach((elem) => {
        let localeKey = elem.getAttribute("data-locale-item");
        elem.innerHTML = `<span>${locales[localeKey]}</span>`;
    });

    let dataPr = document.querySelectorAll('[data-locale-pr]');
    dataPr.forEach((elem) => {
        let localeKey = elem.getAttribute("data-locale-pr");
        elem.setAttribute("placeholder", locales[localeKey]);
    });
}


function getData(url) {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', url, false);
    xhr.send();
    if (xhr.status === 200) {
        return JSON.parse(xhr.responseText);
    }

}

function setManagersOption() {
    let managers = getData('/getFreeManagers');
    let select = document.getElementById('managers');
    let options = "";
    managers.forEach((elem) => {
        options += createList(elem);
    });
    select.innerHTML = options;
}

function createList(element) {
    return `<option value="${element.id}" required>${element.name} ${element.surname}</option>`;
}

function createUtility(event) {

    let name = document.getElementById('utility_name').value;
    let identificationCode = document.getElementById('utility_identificationCode').value;
    let managerSelect = document.getElementById('managers');
    let address;
    let manager;
    try {
        manager = getData('/getUserById?id=' + managerSelect.options[managerSelect.selectedIndex].value);
    } catch (e) {
        manager = null;
    }
    try {
        address = getData('/getAddress?id=' + document.getElementById('address_id').value);
    } catch (e) {
        address = null;
    }

    let utility = {
        name: name,
        active: false,
        address: address,
        identificationCode: identificationCode,
        manager: manager,
        logo: null,
        phoneNumber: phone,
        webSite: website
    };
    event.preventDefault();
    let errors = validateUtility(utility);
    if (Object.keys(errors).length === 0) {
        sendPost(utility);
    } else {
        showMistakesU(errors);
    }
}

let errorUtility = {
    name: document.getElementById("nameError"),
    address: document.getElementById("addressError"),
    identificationCode: document.getElementById("identificationCodeError"),
    manager: document.getElementById("managerError")
};

function showMistakesU(error) {
    clearMistakesU();
    for (let element in error) {
        errorUtility[element].innerHTML = error[element];
        errorUtility[element].classList.add('mistake');
    }
}

function clearMistakesU() {
    for (let element in errorUtility) {
        errorUtility[element].innerHTML = '';
    }
}

function validateUtility(utility) {
    let errors = {};

    if (!/(^([A-Z]+[a-z]*\s*)+\"*([A-Za-z]+\s*.*)+\"*\s*$)|(^([А-ЯІЄЇ]+[а-яієї]*\s*)+\"*([А-ЯІЄЇа-яієї]+\s*.*)+\"*\s*$)/.test(utility.name)) {
        errors.name = locales['utility.name.error'];
    }

    if (utility.address === undefined) {
        errors.address = locales['utility.address.error'];
    }

    if (!/^\d{6,}$/.test(utility.identificationCode)) {
        errors.identificationCode = locales['utility.identificationCode.error'];
    } else if (utility.identificationCode === '') {
        errors.identificationCode = locales['utility.identificationCode.error.size'];
    }

    if (utility.manager === undefined) {
        errors.manager = locales['utility.manager.error'];
    }

    return errors;
}


function sendPost(obj) {
    let errorMessageLabel = document.getElementById("errorMessage");
    let successMessageLabel = document.getElementById("successMessage");
    let nameError = document.getElementById("nameError");
    let addressError = document.getElementById("addressError");
    let identificationCodeError = document.getElementById("identificationCodeError");
    let managerError = document.getElementById("managerError");
    $.ajax({
        type: 'POST',
        url: '/admin/addUtility',
        data: JSON.stringify(obj),
        contentType: 'application/json',
        success: function (response) {
            errorMessageLabel.hidden = true;
            successMessageLabel.hidden = false;
            successMessageLabel.innerHTML = `<div class="alert alert-success" role="alert">${response.success}</div>`;
            setTimeout('location="/admin/utilitiesPage";', 1250);

        },
        error: function (error) {
            let errors = JSON.parse(error.responseText);
            nameError.hidden = false;
            addressError.hidden = false;
            identificationCodeError.hidden = false;
            managerError.hidden = false;
            successMessageLabel.hidden = true;
            if (typeof errors.name != "undefined") {
                nameError.innerHTML = `<b>${errors.name}</b>`;
            } else nameError.innerHTML = `<span class="success-message"><b>${locales.good}</b></span>`;
            ;
            if (typeof errors.address != "undefined") {
                addressError.innerHTML = `<b>${errors.address}</b>`;
            } else addressError.innerHTML = `<span class="success-message"><b>${locales.good}</b></span>`
            if (typeof errors.identificationCode != "undefined") {
                identificationCodeError.innerHTML = `<b >${errors.identificationCode}</b>`;
            } else identificationCodeError.innerHTML = `<span class="success-message"><b>${locales.good}</b></span>`;
            if (typeof errors.manager != "undefined") {
                managerError.innerHTML = `<b>${errors.manager}</b>`;
            } else managerError.innerHTML = `<span class="success-message"><b>${locales.good}</b></span>`;
            errorNotify();

        }
    });
}

// function getUtilities() {
//     let list = getData("/getUtilitiesList");
//     let table = document.getElementById("utility_table");
//     let options = "";
//     list.forEach((elem) => {
//         options += createTable(elem);
//     });
//     table.innerHTML = options;
// }

function createTable(elem) {
    console.log(elem.name);
    let tab = `<tr>
    <td><img src="/logotype?id=+${elem.id}"></td>
    <td>${elem.name}</td>
    <td>${elem.address.regionName}, ${elem.address.cityName}, ${elem.address.streetName}, ${elem.address.houseNumber}, ${elem.address.flatNumber}</td>
    <td>${elem.identificationCode}</td>
    <td>${elem.manager.name} ${elem.manager.surname}</td>
    <td>${elem.phoneNumber} <a href="${elem.webSite}" target="_blank">${elem.webSite}</a></td>
   <td><button class="btn btn-primary btn-sm" data-toggle="modal" data-target="#add_change_logo_modal" data-id="${elem.id}" >${locales.logotype}</button>
   <button class="btn btn-primary btn-sm" data-toggle="modal" data-target="#update_utility_modal" data-id="${elem.id}" >${locales.changeManager}</button> 
   <button class="btn btn-primary btn-sm" data-toggle="modal" data-target="#update_name_utility_modal" data-id="${elem.id}" >${locales.changeName}</button> </td>`

    if (elem.active == true) {
        tab += `<td><a class="btn btn-success btn-sm" href="/utility/setActive?id=+${elem.id}&setActive=+${false}">${locales.active}</a></td></tr>`;
    } else {
        tab += `<td><a class="btn btn-danger btn-sm" href="/utility/setActive?id=+${elem.id}&setActive=+${true}">${locales.inActive}</a></td></tr>`;
    }
    return tab;
}


function changeManagerOption() {
    let managers = getData('/getFreeManagers');
    let select = document.getElementById('update_managers');
    let options = "";
    managers.forEach((elem) => {
        options += createList(elem);
    });
    select.innerHTML = options;
}

function changeManager(event) {
    console.log("update");
    let confirm = document.getElementById("change_manager").value;
    let managerSelect = document.getElementById('update_managers');
    let manager = managerSelect.options[managerSelect.selectedIndex].value;
    let errorMessageLabel = document.getElementById("errorMessageUpdate");
    let successMessageLabel = document.getElementById("successMessageUpdate");
    var Object = {
        keyWord: confirm,
        utilityId: utilityId,
        manager: manager
    };
    event.preventDefault();
    $.ajax({
        type: 'POST',
        url: '/admin/changeManager',
        data: JSON.stringify(Object),
        contentType: 'application/json',
        success: function (response) {
            errorMessageLabel.hidden = true;
            successMessageLabel.hidden = false;
            successMessageLabel.innerHTML = `<div class="alert alert-success" role="alert">${response.success}</div>`;
            setTimeout('location="/admin/utilitiesPage";', 1250);
            successNotify();
        },
        error: function (error) {
            errorMessageLabel.hidden = false;
            successMessageLabel.hidden = true;
            errorMessageLabel.innerHTML = `<div class="alert alert-error" role="alert">${ JSON.parse(error.responseText).keyWord}</div>`;
            errorNotify();
        }
    });
}

function logoView() {
    let logo = document.getElementById("image-cropped-preview2");
    logo.setAttribute("src", "/logotype?id=" + utilityId);

}


function initCropper(file) {
    if (document.getElementById('image-file').files.length === 0) {
        $('#image-editor').addClass('hidden');
        return;
    }
    $('#image-editor').removeClass('hidden');


    image = document.getElementById('image-from-file');
    const imageUrl = URL.createObjectURL(file);
    image.addEventListener('load', () => URL.revokeObjectURL(imageUrl));
    image.src = imageUrl;

    if (cropper != null) {
        cropper.destroy();
        cropper = null;
    }
    cropper = new Cropper(image, {
        aspectRatio: croppedWidth / croppedHeight,
        viewMode: 1,
        dragMode: 'move',
        rotatable: false,
        modal: false,
        background: false,
        crop(event) {
            viewCroppedImage('image-cropped-preview');
        }
    });
    image.addEventListener('zoom', (event) => {
        if ((event.detail.ratio > event.detail.oldRatio) && (event.detail.ratio > 1)) {
            event.preventDefault();
        }
    });
}

function viewCroppedImage(imgId) {
    cropper.getCroppedCanvas({
        width: croppedWidth,
        height: croppedHeight
    }).toBlob(function (blob) {
        let newImg = document.getElementById(imgId);
        const url = URL.createObjectURL(blob);
        newImg.addEventListener('load', () => URL.revokeObjectURL(url));
        newImg.src = url;
    });
}

function apply() {
    viewCroppedImage('image-cropped-preview2');
    document.getElementById('');
    // $('#image-res').removeClass('hidden');
    $('#image-editor').addClass('hidden');
    cropper.getCroppedCanvas({
        width: croppedWidth,
        height: croppedHeight
    }).toBlob(function (blob) {
        imageBlob = blob;
        cropper.destroy();
        cropper = null;

    });

}

function cancel() {
    imageBlob = null;
    cropper.destroy();
cropper = null;
$('#image-editor').addClass('hidden');
document.getElementById('image-file').value = '';


}


function submit(event) {
    event.preventDefault();
    let errorMessageLabel = document.getElementById("errorMessageLogo");
    let successMessageLabel = document.getElementById("successMessageLogo");
    console.log(utilityId);
    let data = {
        'utility_id': utilityId,
    };
    let jsonBlob = new Blob([JSON.stringify(data)], {type: 'application/json;charset=UTF-8;'});
    let ajaxData = new FormData();
    ajaxData.append('info', jsonBlob);
    ajaxData.append('image', imageBlob);
    $.ajax({
        url: '/admin/addLogo',
        method: "POST",
        data: ajaxData,
        processData: false,
        contentType: false,
        // contentType:'multipart/form-data;charset=UTF-8; boundary=l3iPy71otz',
        success: function (response) {
            errorMessageLabel.hidden = true;
            successMessageLabel.hidden = false;
            successMessageLabel.innerHTML = `<div class="alert alert-success" role="alert">${response.success}</div>`;
            setTimeout('location="/admin/utilitiesPage";', 1250);


        },
        error: function (error) {
            errorMessageLabel.hidden = false;
            successMessageLabel.hidden = true;
            errorMessageLabel.innerHTML = JSON.parse(error.responseText).error;
            errorNotify();
        },

    });
}

$('#add_change_logo_modal').on('show.bs.modal', function (e) {
    utilityId = $(e.relatedTarget).data('id');
    logoView();
});

$('#update_utility_modal').on('show.bs.modal', function (e) {
    utilityId = $(e.relatedTarget).data('id');
});
$('#update_name_utility_modal').on('show.bs.modal', function (e) {
    utilityId = $(e.relatedTarget).data('id');
});
// This example displays an address form, using the autocomplete feature
// of the Google Places API to help users fill in the information.

// This example requires the Places library. Include the libraries=places
// parameter when you first load the API. For example:
// <script src="https://maps.googleapis.com/maps/api/js?key=YOUR_API_KEY&libraries=places">
var placeSearch, autocomplete, autocomplete2;
var componentForm = {
    street_number: 'short_name',
    route: 'long_name',
    locality: 'long_name',
    administrative_area_level_1: 'short_name',
    country: 'long_name',
    postal_code: 'short_name'
};


function initAutocomplete() {
    // Create the autocomplete object, restricting the search to geographical
    // location types.
    autocomplete = new google.maps.places.Autocomplete(
        /** @type {!HTMLInputElement} */(document.getElementById('autocomplete')),
        {types: ['geocode']});
    autocomplete2 = new google.maps.places.Autocomplete(
        /** @type {!HTMLInputElement} */(document.getElementById('utility_name')),
        {types: ['establishment']});
    // When the user selects an address from the dropdown, populate the address
    // fields in the form.

    autocomplete2.addListener('place_changed', setName);
    autocomplete.addListener('place_changed', fillInAddress);
}

var utilityPlace
var place;
var latitude;
var longitude;


function setName() {
    utilityPlace = autocomplete2.getPlace();
    if (utilityPlace.name != undefined) {
        document.getElementById('utility_name').value = utilityPlace.name;
        fillInAddressAuto();
    }
    if (utilityPlace.international_phone_number != undefined) {
        phone = utilityPlace.international_phone_number;
    }
    if (utilityPlace.website != undefined) {
        website = utilityPlace.website;
    }
}

function fillInAddress() {
    // Get the place details from the autocomplete object.

    place = autocomplete.getPlace();


    for (var component in componentForm) {
        document.getElementById(component).value = '';
        document.getElementById(component).disabled = false;
        document.getElementById('submit').disabled = false;
        document.getElementById('flat_number').disabled = false;
    }
    latitude = place.geometry.location.lat();
    longitude = place.geometry.location.lng();
    console.log(latitude + " " + longitude);
    // Get each component of the address from the place details
    // and fill the corresponding field on the form.

    for (var i = 0; i < place.address_components.length; i++) {
        var addressType = place.address_components[i].types[0];
        if (componentForm[addressType]) {
            var val = place.address_components[i][componentForm[addressType]];
            document.getElementById(addressType).value = val;
        }
    }
    console.log(place);

}

function fillInAddressAuto() {
    // Get the place details from the autocomplete object.
    if (utilityPlace != undefined) {


        for (var component in componentForm) {
            document.getElementById(component).value = '';
            document.getElementById(component).disabled = false;
            document.getElementById('submit').disabled = false;
            document.getElementById('flat_number').disabled = false;
        }
        latitude = utilityPlace.geometry.location.lat();
        longitude = utilityPlace.geometry.location.lng();
        console.log(latitude + " " + longitude);
        // Get each component of the address from the place details
        // and fill the corresponding field on the form.

        for (var i = 0; i < utilityPlace.address_components.length; i++) {
            var addressType = utilityPlace.address_components[i].types[0];
            if (componentForm[addressType]) {
                var val = utilityPlace.address_components[i][componentForm[addressType]];
                document.getElementById(addressType).value = val;
            }
        }
        console.log(utilityPlace);
    }
    sendData();
}

// Bias the autocomplete object to the user's geographical location,
// as supplied by the browser's 'navigator.geolocation' object.
var curentLocation;

function geolocate() {
    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(function (position) {
            let geolocation = {
                lat: position.coords.latitude,
                lng: position.coords.longitude
            };

            let circle = new google.maps.Circle({
                center: geolocation,
                radius: position.coords.accuracy
            });
            autocomplete.setBounds(circle.getBounds());
        });
    }
}

function sendData() {
    let address_res = document.getElementById("address_result");
    let address = {
        streetNumber: '',
        route: '',
        locality: '',
        region: '',
        country: '',
        postalCode: '',
        flat: '',
        lat: latitude,
        lng: longitude
    };
    address['streetNumber'] = document.getElementById('street_number').value;
    address['route'] = document.getElementById('route').value;
    address['locality'] = document.getElementById('locality').value;
    address['region'] = document.getElementById('administrative_area_level_1').value;
    address['country'] = document.getElementById('country').value;
    address['postalCode'] = document.getElementById('postal_code').value;
    address['flat'] = document.getElementById('flat_number').value;

    console.log(address);
    let errors = validateAddress(address);
    if (Object.keys(errors).length === 0) {
        sendAddress(address);
    } else {
        address_res.setAttribute('class', 'glyphicon glyphicon-remove');
        showMistakes(errors);
    }

}

function showMistakes(error) {
    clearMistakes();
    for (let element in error) {
        errorObject[element].innerHTML = error[element];
        errorObject[element].classList.add('mistake');
    }
}

function clearMistakes() {
    for (let element in errorObject) {
        errorObject[element].innerHTML = '';
    }
}

let errorObject = {
    hn: document.getElementById('street_numberErr'),
    str: document.getElementById('routeErr'),
    ct: document.getElementById('localityErr'),
    r: document.getElementById('administrative_area_level_1Err'),
    c: document.getElementById('postal_codeErr'),
    p: document.getElementById('countryErr'),
    f: document.getElementById('flat_numberErr')
};

function validateAddress(data) {
    let errors = {};

    if (data.streetNumber === '') {
        errors.hn = locales['house.error'];
    }

    if (data.locality === '') {
        errors.ct = locales['city.error'];
    }

    if (data.route === '') {
        errors.str = locales['street.error'];
    }

    if (data.region === '') {
        errors.r = locales['region.error'];
    }

    if (data.country === '') {
        errors.c = locales['country.error'];
    }

    if (!/^(^$|\d{1,3})$/.test(data.flat)) {
        errors.f = locales['flat.error'];
    }

    return errors;
}


function sendAddress(Address) {
    let successMessage = document.getElementById("successMessageAddress");
    let address = document.getElementById("address_result");
    $.ajax({
        type: 'POST',
        url: '/utility/add/address',
        data: JSON.stringify(Address),
        contentType: 'application/json',
        success: function (response) {
            document.getElementById("address_id").setAttribute("value", response);
            successMessage.hidden = false;
            successMessage.innerHTML = `<div class="alert alert-success" role="alert">${locales.addressSuccessfullyCreated}</div>`;
            address.setAttribute('class', 'glyphicon glyphicon-ok');



        },
        error: function (error) {

            address.setAttribute('class', 'glyphicon glyphicon-remove');
            new PNotify({
                title: locales.error,
                type: 'error',
                styling: 'bootstrap3'
            });
        }
    });
}

var pacContainerInitialized = false;
$('#autocomplete').keypress(function () {
    if (!pacContainerInitialized) {
        $('.pac-container').css('z-index', '9999');
        pacContainerInitialized = true;
    }
});
$('#utility_name').keypress(function () {
    if (!pacContainerInitialized) {
        $('.pac-container').css('z-index', '9999');
        pacContainerInitialized = true;
    }
});
$('#map').keypress(function () {
    if (!pacContainerInitialized) {
        $('.pac-container').css('z-index', '9999');
        pacContainerInitialized = true;
    }
});


function changeLegalName(event) {
    let confirm = document.getElementById("change_name_confirm").value;
    let name = document.getElementById("change_name").value;
    let errorMessageLabel = document.getElementById("errorMessageUpdateName");
    let successMessageLabel = document.getElementById("successMessageUpdateName");
    var Object = {
        keyWord: confirm,
        utilityId: utilityId,
        legalName: name
    };
    event.preventDefault();
    $.ajax({
        type: 'POST',
        url: '/admin/changeName',
        data: JSON.stringify(Object),
        contentType: 'application/json',
        success: function (response) {
            errorMessageLabel.hidden = true;
            successMessageLabel.hidden = false;
            successMessageLabel.innerHTML = `<div class="alert alert-success" role="alert">${response.success}</div>`;
            setTimeout('location="/admin/utilitiesPage";', 1250);

        },
        error: function (error) {
            let errors = JSON.parse(error.responseText);
            errorMessageLabel.hidden = false;
            successMessageLabel.hidden = true;
            if (typeof errors.legalName != "undefined") {
                errorMessageLabel.innerHTML = `<div class="alert alert-error" role="alert">${errors.legalName}</div>`;
                ;
            } else if (typeof errors.keyWord != "undefined") {
                errorMessageLabel.innerHTML = `<div class="alert alert-error" role="alert">${errors.keyWord}</div>`;
            }
            errorNotify();
        }
    });
}

function successNotify() {
    PNotify.removeAll();
    new PNotify({
        title: locales.success,
        type: 'success',
        styling: 'bootstrap3'
    });
}

function errorNotify() {
    PNotify.removeAll();
    new PNotify({
        title: locales.error,
        type: 'error',
        styling: 'bootstrap3'
    });
}

function warningNotify() {
    PNotify.removeAll();
    new PNotify({
        title: locales['warning'],
        type: 'warning',
        styling: 'bootstrap3'
    });
}


function setPagination() {
    $.get({
        url: '/utilities/get/pages',
        success: function (data) {
            $('#utilities-pagination').twbsPagination({
                first: locales["paginationFirst"],
                prev: locales["paginationPrevious"],
                next: locales["paginationNext"],
                last: locales["paginationLast"],
                totalPages: data,
                visiblePages: 10,
                onPageClick: function (event, page) {
                    getUtilities(page);
                }
            });
        }
    });
}

function getUtilities(page) {
    jQuery.ajax({
        url: '/getUtilitiesList/' + page,
        type: 'GET',
        dataType: 'json',
        success: function (data) {
            let table = document.getElementById("utility_table");
            let options = "";
            console.log(data);
            $.each(data, function (index, element) {
                options += createTable(element);
            });
            table.innerHTML = options;
        },
        error: function (jqXHR, textStatus, errorThrown) {
            new PNotify({
                title: locales['error'],
                type: 'error',
                styling: 'bootstrap3',
                delay: 1000
            });
        },
        timeout: 120000,
    });
}

