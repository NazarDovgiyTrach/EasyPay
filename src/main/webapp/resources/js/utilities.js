(function () {
    getListOfUtilities();
}());


function getData(url) {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', url, false);
    xhr.send();
    if (xhr.status === 200) {
        return JSON.parse(xhr.responseText);
    }
}

function getListOfUtilities() {
    let utilities = getData('/utilities');
    console.log(utilities);
    let cards = document.getElementById('cards');
    let card = "";
    utilities.forEach((elem) => {
        card += createCardBoody(elem);
    });
    cards.innerHTML = card;
}

function createCardBoody(elem) {
    let local = getData('/getMessages');
    let str = `
<div class="col-md-6 col-sm-6 col-xs-12">
  <div class="x_panel">
      <div class="x_title">
           <h2>
                <a href="user/utility?id=${elem.id}">${elem.name}</a>
            </h2>
       <div class="clearfix"></div>
        </div>
  </div>
`
    let flag = getData('/isConnected?id=' + elem.id + '&addressId=' + new URL(window.location.href).searchParams.get('addressId'));
    console.log('/isConnected?id=' + elem.id + '&addressId=' + new URL(window.location.href).searchParams.get('addressId'));
    if (flag) {
        str += `
    <div class="x_content">
        <canvas id="lineChart"></canvas>
         <a class="btn btn-primary mt-2"  type="button" href="/user/connectUtility?utilityId=${elem.id}&addressId=${new URL(window.location.href).searchParams.get('addressId')}">${local.connect}</a>
    </div>
    </div>
    `
    } else {
        str += `
    <div class="x_content">
        <canvas id="lineChart"></canvas>
        <a class="btn btn-primary mt-2"  disabled="true">${local.connected}</a>
    </div>
    </div>
    `
    }
    return str;
}