document.getElementById('submit').addEventListener('click', sendData);
document.getElementById('flat_checkbox').addEventListener('click', checkFlat);


let local = getData('/getMessages');
let errorObject = {
    hn: document.getElementById('street_numberErr'),
    str: document.getElementById('routeErr'),
    ct: document.getElementById('localityErr'),
    r: document.getElementById('administrative_area_level_1Err'),
    c: document.getElementById('postal_codeErr'),
    p: document.getElementById('countryErr'),
    f: document.getElementById('flat_numberErr')
};
(function () {
    init();
    setPagination();
}());
function getData(url){
    var xhr = new XMLHttpRequest();
    xhr.open('GET', url, false);
    xhr.send();
    if (xhr.status === 200) {
        return JSON.parse(xhr.responseText);
    }
}
function init() {
    document.getElementById('addresses').innerHTML = `<span>${local.addresses}</span>`
}
function checkFlat() {
    let checkbox = document.getElementById('flat_checkbox');
    if (checkbox.checked == true) {
        document.getElementById('flat_number').disabled = false;
    }
    if (checkbox.checked == false) {
        document.getElementById('flat_number').disabled = true;
    }
}

function sendPost(obj) {
    $.ajax({
        type: 'POST',
        url: '/add/address',
        data: JSON.stringify(obj),
        contentType: 'application/json',
        success: function (data) {
            window.location = '/user/addresses'
        },
        error : function(error) {
            PNotify.removeAll();
            new PNotify({
                title: 'Login Failed',
                text: error.responseText,
                type: 'error',
                styling: 'bootstrap3'
            });
        }
    });
}
var listOfAddresses;
function getList() {
    listOfAddresses = getData("/listById");
    let tbody = document.getElementById("address_table");
    let options = "";
    listOfAddresses.forEach((elem) => {
        options += buildList(elem);
    });
    tbody.innerHTML = options;
}

function buildList(elem) {
    console.log(elem);
    let str = `<tr>
    <td>${elem.region.name}</td>
    <td>${elem.city.name}</td>
    <td>${elem.street.name}</td>
    <td>${elem.house.number}</td>
    <td>${elem.flat.number}</td>
    <td>${elem.active}</td>
    <td><a class="btn btn-default" href="/user/utilities?addressId=${elem.id}">${local.utilities}</a></td>`;
     if (elem.active == true){
         str +=`<td><a class="btn btn-warning" href="/address/disconnect?id=+${elem.id}">${local.disconnect}</a></td></tr>`;
     } else {
         str+=`<td><a class="btn btn-primary"  href="/address/connect?id=+${elem.id}">${local.connect}</a></td></tr>`;
     }
    return str;
}
// This example displays an address form, using the autocomplete feature
// of the Google Places API to help users fill in the information.

// This example requires the Places library. Include the libraries=places
// parameter when you first load the API. For example:
// <script src="https://maps.googleapis.com/maps/api/js?key=YOUR_API_KEY&libraries=places">
var placeSearch, autocomplete;
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

    // When the user selects an address from the dropdown, populate the address
    // fields in the form.
    autocomplete.addListener('place_changed', fillInAddress);
}
var place;
var latitude;
var longitude;
function fillInAddress() {
    // Get the place details from the autocomplete object.
    place = autocomplete.getPlace();

    for (var component in componentForm) {
        document.getElementById(component).value = '';
        document.getElementById(component).disabled = false;
        document.getElementById('submit').disabled = false;
        document.getElementById('flat_checkbox').disabled = false;
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
}
// Bias the autocomplete object to the user's geographical location,
// as supplied by the browser's 'navigator.geolocation' object.
function geolocate() {
    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(function(position) {
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
    let checkbox = document.getElementById('flat_checkbox');
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
    if (checkbox.checked == true) {
        address['flat'] = document.getElementById('flat_number').value;
    }
    let errors = validateAddress(address);
    if(Object.keys(errors).length === 0) {
        sendPost(address);
    } else {
        showMistakes(errors);
    }
}

function showMistakes(error){
    clearMistakes();
    for(let element in error){
        errorObject[element].innerHTML = error[element];
        errorObject[element].classList.add('mistake');
    }
}

function clearMistakes() {
    for(let element in errorObject){
        errorObject[element].innerHTML = '';
    }
}

function validateAddress(data) {
    let errors = {};
    console.log(data);
    if(data.streetNumber === ''){
        errors.hn = "House contain at least 1 characters!";
    } else if(!/^\d{1,3}(|[A-ZА-ЯІЇЄ]{1})$/.test(data.streetNumber)){
        errors.hn = "House can contain only latin letter and number!";
    }

    if(data.locality === ''){
        errors.ct = "City contain at least 1 characters!";
    } else if(!/^[A-ZА-ЯІЇЄ][a-zа-яіїє]{1,30}([\-\s][A-ZА-ЯІЇЄa-zа-я][a-zа-яіїє]{1,30}|)$/.test(data.locality)){
        errors.ct = "City can contain only latin letter and number!";
    }

    if(data.route === ''){
        errors.str = "Street contain at least 1 characters!";
    } else if(!/^([A-Za-zА-ЯІЇЄа-яіїє]{1,30})([\-\s][A-Za-zА-ЯІЇЄа-яіїє]{1,30}|)$/.test(data.route)){
        errors.str = "Street can contain only latin letter!";
    }

    if(data.region === ''){
        errors.r = "Region contain at least 1 characters!";
    } else if(!/^(([A-Za-zА-ЯІЇЄа-яіїє'\-]){1,30})([\-\s][A-Za-zА-ЯІЇЄа-яіїє]{1,30})$/.test(data.region)){
        errors.r = "Region can contain only latin letter!";
    }

    if(data.country === ''){
        errors.c = "Country contain at least 1 characters!";
    } else if(!/^[A-ZА-ЯІЇЄ][a-zа-яіїє]{1,30}([\-\s][A-ZА-ЯІЇЄa-zа-я][a-zа-яіїє]{1,30}|)$/.test(data.country)){
        errors.c = "Country can contain only latin letter!";
    }

    if (!/^(^$|\d{1,3})$/.test(data.flat)) {
        errors.f = "Flat can contain 3 characters!";
    }

    return errors;
}


function setPagination() {
    $.get({
        url: '/user/addresses/get/pages',
        success: function (data) {
            $('#address-pagination').twbsPagination({
                first: local["paginationFirst"],
                prev: local["paginationPrevious"],
                next: local["paginationNext"],
                last: local["paginationLast"],
                totalPages: data,
                visiblePages: 10,
                onPageClick: function (event, page) {
                    getUserAddresses(page);
                }
            });
        }
    });
}

function getUserAddresses(page) {
    jQuery.ajax({
        url: '/user/addresses/pagination/'+page,
        type: 'GET',
        dataType: 'json',
        success: function (data) {
            let tbody = document.getElementById("address_table");
            let options = "";
            console.log(data);
            $.each(data, function (index, element) {
                options += buildList(element);
                console.log(element);
            });
            tbody.innerHTML = options;
        },
        error: function (jqXHR, textStatus, errorThrown) {
            new PNotify({
                title: locales['error'],
                text: locales['somethingWentWrong'],
                type: 'error',
                styling: 'bootstrap3',
                delay: 1000
            });
        },
        timeout: 120000,
    });
}
