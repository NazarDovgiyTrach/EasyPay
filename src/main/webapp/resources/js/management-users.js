document.getElementById("updateRole").addEventListener("click", update.bind(this));
document.getElementById("updateActive").addEventListener("click", update.bind(this));

let selectedUser;
let isActive;

(function() {
    getAllUsers();
}());

function getAllUsers() {
   let table = $('#user-list').DataTable( {
        ajax: "/admin/users",
        columns: [
            { data: "surname" },
            { data: "name" },
            { data: "role" },
            { data: "email" },
            { data: "phoneNumber" },
            { data: null,
                "searchable": false,
                "orderable": false,
                defaultContent: `<button class="btn btn-success" data-toggle="modal" data-target="#change-role" title="change role"><span class="fa fa-edit  "></span></button>` },
            { data: "userStatus",
                "searchable": false,
                "orderable": false,
                "render": function(data, type, row) {
                    if (row.userStatus === "ACTIVE") {
                        return `<a id="${row.id}" class="btn btn-danger" data-toggle="modal" data-target="#change-active" title="ban"><i id="${row.id}" class="fa fa-ban"></i></a>`;
                    } else if (row.userStatus === "BANNED"){
                        return `<a id="${row.id}" class="btn btn-success" data-toggle="modal" data-target="#change-active" title="unBan"><i id="${row.id}" class="fa fa-level-up"></i></a>`;
                    }
                }},
        ]
    } );
    $('#user-list tbody').on( 'click', 'button', function () {
        let data = table.row( $(this).parents('tr') ).data();
        selectedUser = data["id"];
        setRoleInSelect(data["role"]);
        setUserActive(data.userStatus);
    } );
    $('#user-list tbody').on( 'click', 'a', function () {
        let data = table.row( $(this).parents('tr') ).data();
        selectedUser = data["id"];
        setUserActive(data.userStatus === "ACTIVE" ? "BANNED" : "ACTIVE");
        document.getElementById("role").value = data["role"];
    } );
    /*fetch('/admin/users')
        .then(function(response) {
            return response.json();
        })
        .then(function(data) {
            let table = $("user-list").DataTable({
                data : data
            });
            /!*data.forEach((element) => {
                table += addRow(element);
            });*!/
            console.log(table.rows( 0 ).data());
            //document.getElementById("user-list").innerHTML = table;
        });*/
}

(function () {
    fetch('/roles')
        .then(function (response) {
            return response.json();
        })
        .then(function (data) {
            let select = "";
            data.forEach((element) => {
                select += addOption(element);
            });
            document.getElementById("role").innerHTML = select;
        })
}());

function addOption(element) {
    return `<option>${element}</option>`
}

function update() {
    let user = {
        id: selectedUser,
        role: getRole(),
        status: isActive
    };
    fetch('/admin/users/update', {
        method: 'PUT',
        body: JSON.stringify(user),
        headers:{
            'Content-Type': 'application/json'
        }
    })
        .then(function(response) {
            if (response.ok) {
                location.reload();
                document.getElementById("closeChangeRole").click();
                new PNotify({
                    title: 'Regular Success',
                    text: 'That thing that you were trying to do worked!',
                    type: 'success',
                    styling: 'bootstrap3'
                });
            }
        })
}

function addRow(element){

    let str = `<tr>   
                    <td>${element.name}</td>
                    <td>${element.surname}</td>
                    <td>${element.role}</td>
                    <td>${element.email}</td>       
                    <td>${element.phoneNumber}</td>`;
    if (element.lastLogin != null) {
        str += `<td>${element.lastLogin.dayOfMonth} ${element.lastLogin.month} ${element.lastLogin.year}</td>`
    } else {
        str += `<td></td>`
    }
    str += `<td><a id="${element.id}" class="btn btn-success" onclick="setRoleInSelect('${element.role}')" data-toggle="modal" data-target="#change-role" title="change role"><i id="${element.id}" class="fa fa-edit"></i></a></td>`;

    if (element.active) str += `<td><a id="${element.id}" class="btn btn-danger" onclick="setUserActive('false')" data-toggle="modal" data-target="#change-active" title="ban"><i id="${element.id}" class="fa fa-ban"></i></a></td></tr>`;
    else str += `<td><a id="${element.id}" class="btn btn-success" onclick="setUserActive('true')" data-toggle="modal" data-target="#change-active" title="unBan"><i id="${element.id}" class="fa fa-level-up"></i></a></td></tr>`;

    return str;
}

function setRoleInSelect(role) {
    document.getElementById("role").value = role;
}

document.getElementById("datatable").addEventListener("click", method.bind(this));

function method(event) {
    selectedUser = event.target.id;
    return selectedUser;
}

function getRole() {
    return document.getElementById("role").value;
}

function setUserActive(active) {
    isActive = active;
}
