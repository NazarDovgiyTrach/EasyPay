document.getElementById("regions").addEventListener("change", getCitiesByRegionId.bind(this));
document.getElementById("cities").addEventListener("change", getStreetByCityId.bind(this));
document.getElementById("streets").addEventListener("click", getHouseByStreetId.bind(this));
document.getElementById("houses").addEventListener("click", getFlatByHouseId.bind(this));
document.getElementById("createRegion").addEventListener("click", createRegion.bind(this));
document.getElementById("createCity").addEventListener("click", createCity.bind(this));
document.getElementById("createStreet").addEventListener("click", createStreet.bind(this));
document.getElementById("createHouse").addEventListener("click", createHouse.bind(this));
document.getElementById("createFlat").addEventListener("click", createFlat.bind(this));

(function getAllRegions() {
    fetch('/regions')
        .then(function (response) {
            return response.json();
        })
        .then(function (data) {
            let select = "<option disabled selected>Choose region</option>";
            data.forEach((element) => {
                select += addNameOption(element);
            });
            document.getElementById("regions").innerHTML = select;
        });
}());

function getCitiesByRegionId() {
    let selectedRegionId = document.getElementById("regions").value;
    fetch('/regions/get-cities-by-id/' + selectedRegionId)
        .then(function (response) {
            return response.json();
        })
        .then(function (data) {
            let select = "<option disabled selected>Choose city</option>";
            data.forEach((element) => {
                select += addNameOption(element);
            });
            document.getElementById("cities").innerHTML = select;
        });
}

function getStreetByCityId() {
    let selectedCityId = document.getElementById("cities").value;
    fetch('/cities/get-streets-by-id/' + selectedCityId)
        .then(function (response) {
            return response.json();
        })
        .then(function (data) {
            let select = "<option disabled selected>Choose street</option>";
            data.forEach((element) => {
                select += addNameOption(element);
            });
            document.getElementById("streets").innerHTML = select;
        });
}

function getHouseByStreetId() {
    let selectedStreetId = document.getElementById("streets").value;
    fetch('/streets/get-houses-by-id/' + selectedStreetId)
        .then(function (response) {
            return response.json();
        })
        .then(function (data) {
            let select = "<option disabled selected>Choose house</option>";
            data.forEach((element) => {
                select += addNumberOption(element);
            });
            document.getElementById("houses").innerHTML = select;
        });
}

function getFlatByHouseId() {
    let selectedHouseId = document.getElementById("houses").value;
    fetch('/houses/get-flats-by-id/' + selectedHouseId)
        .then(function (response) {
            return response.json();
        })
        .then(function (data) {
            let select = "<option disabled selected>Choose flat</option>";
            data.forEach((element) => {
                select += addNumberOption(element);
            });
            document.getElementById("flats").innerHTML = select;
        });
}

function createRegion(event) {
    event.preventDefault();
    let isErrorExists = false;
    let region = {
        name: document.getElementById('region').value
    };
    fetch('/admin/address/region', {
        method: 'POST',
        body: JSON.stringify(region),
        headers: {
            'Content-Type': 'application/json'
        }
    })
        .then(function (response) {
            if (response.ok) {
                showMessage('Success!!!', 'The region has been successfully created!', 'success');
                document.getElementById("region").value = "";
                fetch('/regions')
                    .then(function (response) {
                        return response.json();
                    })
                    .then(function (data) {
                        let select = "<option disabled selected>Choose region</option>";
                        data.forEach((element) => {
                            select += addNameOption(element);
                        });
                        document.getElementById("regions").innerHTML = select;
                    });
            } else {
                isErrorExists = true;
            }
            return response.json();
        })
        .then(function (data) {
            if (isErrorExists) {
                showMessage('Failed!!!', data.name == null ? data.uniqueness : data.name, 'error');
            }
        })
}

function createCity(event) {
    event.preventDefault();
    let isErrorExists = false;
    let city = {
        name: document.getElementById('city').value,
        regionId: document.getElementById('regions').value
    };
    fetch('/admin/address/city', {
        method: 'POST',
        body: JSON.stringify(city),
        headers: {
            'Content-Type': 'application/json'
        }
    })
        .then(function (response) {
            if (response.ok) {
                showMessage('Success', 'The city has been successfully created!', 'success');
                document.getElementById("city").value = "";
                getCitiesByRegionId();
            } else {
                isErrorExists = true;
            }
            return response.json();
        })
        .then(function (data) {
            if (isErrorExists) {
                console.log(data);
                showMessage('Failed!!!', data.name == null ? data.uniqueness : data.name, 'error');
            }
        })
}

function createStreet(event) {
    event.preventDefault();
    let isErrorExists = false;
    let street = {
        name: document.getElementById('street').value,
        cityId: document.getElementById('cities').value
    };
    fetch('/admin/address/street', {
        method: 'POST',
        body: JSON.stringify(street),
        headers: {
            'Content-Type': 'application/json'
        }
    })
        .then(function (response) {
            if (response.ok) {
                showMessage('Success', 'The street has been successfully created!', 'success');
                document.getElementById("street").value = "";
                getStreetByCityId();
            } else {
                isErrorExists = true;
            }
            return response.json();
        })
        .then(function (data) {
            if (isErrorExists) {
                showMessage('Failed!!!', data.name, 'error')
            }
        })
}

function createHouse(event) {
    event.preventDefault();
    let isErrorExists = false;
    let house = {
        number: document.getElementById('house').value,
        streetId: document.getElementById('streets').value
    };
    fetch('/admin/address/house', {
        method: 'POST',
        body: JSON.stringify(house),
        headers: {
            'Content-Type': 'application/json'
        }
    })
        .then(function (response) {
            if (response.ok) {
                showMessage('Success', 'The house has been successfully created!', 'success');
                document.getElementById("house").value = "";
                getHouseByStreetId();
            } else {
                isErrorExists = true;
            }
            return response.json();
        })
        .then(function (data) {
            if (isErrorExists) {
                showMessage('Failed!!!', data.number, 'error')
            }
        })
}

function createFlat(event) {
    event.preventDefault();
    let isErrorExists = false;
    let flat = {
        number: document.getElementById('flat').value,
        houseId: document.getElementById('houses').value
    };
    console.log(flat);
    fetch('/admin/address/flat', {
        method: 'POST',
        body: JSON.stringify(flat),
        headers: {
            'Content-Type': 'application/json'
        }
    })
        .then(function (response) {
            if (response.ok) {
                showMessage('Success', 'The flat has been successfully created!', 'success');
                document.getElementById("flat").value = "";
                getFlatByHouseId();
            } else {
                isErrorExists = true;
            }
            return response.json();
        })
        .then(function (data) {
            if (isErrorExists) {
                showMessage('Failed!!!', data.number, 'error')
            }
        })
}

function showMessage(title, text, type) {
    PNotify.removeAll();
    new PNotify({
        title: title,
        text: text,
        type: type,
        styling: 'bootstrap3'
    });
}

function addNameOption(element) {
    return `<option value="${element.id}">${element.name}</option>`;
}

function addNumberOption(element) {
    return `<option value="${element.id}">${element.number}</option>`;
}