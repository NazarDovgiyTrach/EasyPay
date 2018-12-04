document.getElementById("updateRole").addEventListener("click", update.bind(this));
document.getElementById("updateUserStatus").addEventListener("click", update.bind(this));

let selectedUserId;
let newRole;
let newStatus;

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

(function () {
    setPagination();
}());

function setPagination() {
    $.get({
        url: '/admin/pages',
        success: function (data) {
            $('#user-pagination').twbsPagination({
                totalPages: data,
                visiblePages: 10,
                onPageClick: function (event, page) {
                    getUsers(page);
                }
            });
        }
    });
}

function getUsers(page) {
    jQuery.ajax({
        url: '/admin/users?firstResult='+page,
        type: 'GET',
        dataType: 'json',
        success: function (data) {
            let tbody = document.getElementById("users-table");
            let options = "";
            $.each(data, function (index, element) {
                options += buildList(element);
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

function buildList(elem) {
    let str = `<tr>
    <td>${elem.surname}</td>
    <td>${elem.name}</td>
    <td>${elem.role}</td>
    <td>${elem.email}</td>
    <td>${elem.phoneNumber}</td>
    <td><button class="btn btn-success" onclick="setData('${elem.id}', '${elem.role}', '${elem.userStatus}')" data-toggle="modal" data-target="#change-role" title="change role"><span class="fa fa-edit  "></span></button></td>`;

    if (elem.userStatus === "ACTIVE") str += `<td><a class="btn btn-danger" onclick="setData('${elem.id}', '${elem.role}', 'BANNED')" data-toggle="modal" data-target="#change-active" title="ban"><i class="fa fa-ban"></i></a></td></tr>`;
    else str += `<td><a class="btn btn-success" onclick="setData('${elem.id}', '${elem.role}', 'ACTIVE')", data-toggle="modal" data-target="#change-active" title="unBan"><i class="fa fa-level-up"></i></a></td></tr>`;

    return str;
}

function setData(id, role, status) {
    selectedUserId = id;
    newRole = role;
    newStatus = status;
    document.getElementById("role").value = role;
}

function update() {
    event.preventDefault();
    newRole = document.getElementById("role").value;
    let user = {
        id: selectedUserId,
        role: newRole,
        status: newStatus
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
                setPagination();
                location.reload();
                document.getElementById("closeChangeRole").click();
                document.getElementById("closeChangeStatus").click();
                new PNotify({
                    title: 'Success!!!',
                    text: 'User has been successfully updated',
                    type: 'success',
                    styling: 'bootstrap3'
                });
            } else {
                new PNotify({
                    title: locales['error'],
                    text: locales['somethingWentWrong'],
                    type: 'error',
                    styling: 'bootstrap3',
                    delay: 1000
                });
            }
        })
}