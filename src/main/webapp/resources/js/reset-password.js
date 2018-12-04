$("#changePasswordForm").submit(changePassword);
function changePassword(event) {
    event.preventDefault();
    let password = $("#password").val();
    let confirmPassword = $("#passwordConfirm").val();
    if(password !== confirmPassword) {
        errorNotify(locales['passwordMatchesError']);
    }
    else if(!/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{7,}$/.test(password)) {
        errorNotify(locales['passwordInvalid']);
    }
    else {
        $.ajax({
            type: 'POST',
            url: '/changePassword',
            contentType: 'application/json',
            data: JSON.stringify({
                password: password,
                confirmPassword: confirmPassword
            }),
            success: function (response) {
                window.location.replace("/loginPage?resetPassword");
            },
            error: function (error) {
                errorNotify(error.responseJSON.message);
            }
        });
    }
}

function errorNotify(message) {
    PNotify.removeAll();
    new PNotify({
        title: locales['error'],
        text: message,
        type: 'error',
        styling: 'bootstrap3'
    });
}