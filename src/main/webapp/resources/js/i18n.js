let locales = getData("/getMessages");
(function () {
    createLocalesFilds();

}());

function createLocalesFilds() {
    try {
        document.getElementById("dropdown-menu-logOut").innerHTML = `<i class="fa fa-sign-out pull-right"></i><span>${locales.logOut}</span>`;
        document.getElementById("New_to_site").innerHTML = `<span>${locales.newToSite} <a href="registrationPage" class="to_register" >${locales.createAccount}</a></span>`;
    } catch (e) {
    }


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

    let dataValue = document.querySelectorAll('[data-locale-value]');
    dataValue.forEach((elem) => {
        let localeKey = elem.getAttribute("data-locale-value");
        elem.setAttribute("value", locales[localeKey]);
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

//
// function getData(url) {
//     var xhr = new XMLHttpRequest();
//     var response;
//     xhr.open('GET', url);
//     xhr.onreadystatechange = function () {
//         if (xhr.readyState === 4 && xhr.status === 200) {
//             response = JSON.parse(xhr.responseText);
//         }
//     }
//     xhr.send();
// }
