document.getElementById('submit').addEventListener('click', call);

let utility;
let id;

$('#selectAddress').on('change', function(e){
    setUtilities();
});

$('#picker').datepicker({
    format: "yyyy-mm-dd",
    weekStart: 1,
    startDate: "tomorrow",
    autoclose: true,
    todayHighlight: true
});


function sendPost(obj) {
    $.ajax({
        type: 'POST',
        url: '/call/inspector',
        data: JSON.stringify(obj),
        contentType: 'application/json',
        success: function (data) {
            window.location = '/user/connected-utilities/';
        }
    });
}
function buildList(elem) {
    let local = getData('/getMessages');
    let addressId = $('#selectAddress').val();
    let str = `<tr>
    <td>${elem.name}</td>
    <td><button id= "preCall" onclick="setUId()" type="button" class="btn btn-primary mt-2" data-toggle="modal" data-id="${elem.id}" data-target="#call_inspector_modal">${local.callInspector}</button></td>
    `;
    str +=`<td><a id="disc" class="btn btn-warning" href="/user/disconnectUtility?utilityId=${elem.id}&addressId=${addressId}">${local.disconnect}</a></td></tr>`;
    return str;
}


function call() {
    let date = $('#picker').val();
    let call = {
        utilityId: id,
        date: date
    };
    sendPost(call);
}

function setUtilities(){
    $.ajax({
        type: 'GET',
        url: '/user/payments?id=' + $('#selectAddress').val(),
        success: function (response) {
            let tbody = $('#historyTable > tbody');
            let options = "";

            response.forEach((elem) => {
                options += buildList(elem);
            });

            $(tbody).html(options);
        },
        timeout: 120000
    });
}

$(document).ready(
    function () {
        let addresses = [];

        $.ajax({
            type: 'GET',
            url: '/listById',
            contentType: 'application/json; charset=utf-8',
            success: function (response) {
                addresses = response;
                $.each(addresses, function () {
                    $('#selectAddress').append($("<option></option>")
                        .attr("value", this.id)
                        .text(getFullAddress(this)));
                });

                setUtilities();

            },
            error: function (jqXHR, textStatus, errorThrown) {

            },

            timeout: 120000
        });


    }
);

function setUId() {
    let ut = event.target;
    id = ut.getAttribute('data-id');
}

function getFullAddress(address) {
    return address.city.name + ' City, '
        + address.street.name + ' Str., ' + address.house.number
        + '/' + address.flat.number;
}



