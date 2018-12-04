$("#forgotPasswordForm").submit(sendForgotPasswordMailWithToken);
function sendForgotPasswordMailWithToken(event) {
    let email = $("#email").val();
    let btnReset = $("#btnReset");
    btnReset.attr("disabled", true);
    event.preventDefault();
    $.ajax({
        type: 'POST',
        url: '/forgotPassword',
        data: {
            email: email
        },
        success: function (data) {
            btnReset.attr("disabled", false);
            successNotify(data.message)
        },
        error : function(error) {
            btnReset.attr("disabled", false);
            errorNotify(error.responseJSON.message);
        }
    });
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

function successNotify(message) {
    PNotify.removeAll();
    new PNotify({
        title: locales['success'],
        text: message,
        type: 'success',
        styling: 'bootstrap3'
    });
}

(function () {
    let urlParams = new URLSearchParams(window.location.search);
    if(urlParams.has('tokenInvalid')){
        errorNotify(locales['tokenInvalid']);
    }
})();