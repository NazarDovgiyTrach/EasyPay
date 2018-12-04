$('#addPhoneForm').on('submit', function (event) {
    event.preventDefault();
	if (validatePhone()) {
	    $.ajax({
            url: '/social/registration/finish',
            type: 'POST',
            data: {phoneNumber: $('#phone').val()},
            success: function () {
                window.location.replace("/home");
            },
            error: function (error) {
                PNotify.removeAll();
                new PNotify({
                    title: type,
                    text: 'something went wrong!',
                    type: 'error',
                    styling: 'bootstrap3',
                    delay: 2000
                });
            }
        });
    }
});

function validatePhone() {
    let phoneNumber = $('#phone').val();
    let phoneNumberErrors = $('#phoneErr');

    if(phoneNumber === '') {
        phoneNumberErrors.html("Phone number is required!");
        return false;
    } else if(!/^(\+\d{12})$/.test(phoneNumber)) {
       phoneNumberErrors.html("First sign must be + then your full phone number!");
       return false;
    }
    return true;
}