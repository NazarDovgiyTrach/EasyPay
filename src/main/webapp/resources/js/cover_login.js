$("#loginForm").submit(login);
function login(event) {
    let email = $("#loginEmail").val();
    let password = $("#loginPassword").val();
    event.preventDefault();
    $.ajax({
        type: 'POST',
        url: '/authorization',
        contentType: 'application/json',
        data: JSON.stringify({
            'email': email,
            'password': password
        }),
        success: function (response) {
           window.location.replace("/home");
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

(function selfInvoke() {
    let urlParams = new URLSearchParams(window.location.search);
    if(urlParams.has('logout')){
        PNotify.removeAll();
        new PNotify({
            title: 'Logout Success',
            text: 'You have been successfully logged out!',
            type: 'success',
            styling: 'bootstrap3',
            delay: 3000
        });
    }
    else if(urlParams.has('resetPassword')){
        PNotify.removeAll();
        new PNotify({
            title: 'Password Changed',
            text: 'Your password has been successfully changed!',
            type: 'success',
            styling: 'bootstrap3',
            delay: 3000
        });
    }
})();