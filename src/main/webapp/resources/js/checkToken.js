(function () {
    let urlParams = new URLSearchParams(window.location.search);
    if(urlParams.has('tokenInvalid')){
        PNotify.removeAll();
        new PNotify({
            title: 'Confirmation failed! Try again.',
            text: 'Token is expired or invalid!',
            type: 'error',
            styling: 'bootstrap3'
        });
    }
}());