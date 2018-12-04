const croppedWidth = 200;
const croppedHeight = 200;
let imageBlob = null;
let cropper;
let image;

const profileUpdateURL = '/profile/update';
const myProfileURL = '/profile/my';
let password;
let newPassword;
let newPasswordRepeat;
let nameError;
let surnameError;
let phoneNumberError;
let passwordError;
let passwordRequiredError;
let passwordDontMathesError;
let name;
let surname;
let phoneNumber;
let email;





let user;
function setValues(response) {
    name.value = response.name;
    surname.value = response.surname;
    phoneNumber.value = response.phoneNumber;
    email = response.email;
    if (response.password === null){
       document.getElementById('reset-password-button') .classList.remove('hidden');
       $("password").attr("disabled", true);
       $("new-password").attr("disabled", true);
       $("password-repeat").attr("disabled", true);
    }
    else {
        $("#reset-password-button").attr("disabled", true);
        document.getElementById('change-password-block') .classList.remove('hidden');
    }
}


function getUserFromServer() {
    $.ajax({
        type: "GET",
        url: myProfileURL,
        success: function (response) {
            setValues(response);
        }
    });

}




function initCropper(file) {
    if(document.getElementById('image-file').files.length === 0){
        $('#image-editor').addClass('hidden');
        return;
    }
    $('#image-editor').removeClass('hidden');

    
    image = document.getElementById('image-from-file');
    const  imageUrl = URL.createObjectURL(file);
    image.addEventListener('load', () => URL.revokeObjectURL(imageUrl));
    image.src  = imageUrl;

    if (cropper != null){
        cropper.destroy();
        cropper = null;
    }
    cropper = new Cropper(image, {
        aspectRatio: croppedWidth/croppedHeight,
        viewMode: 1,
        dragMode: 'move',
        rotatable: false,
        modal: false,
        background:false,
        crop(event) {
            viewCroppedImage('image-cropped-preview');
        }
    });
    image.addEventListener('zoom', (event) => {
        if ((event.detail.ratio > event.detail.oldRatio)&&(event.detail.ratio>1)) {
           event.preventDefault();
        }
    });
}


function viewCroppedImage(imgId) {
    let canvas = cropper.getCroppedCanvas({
        width:croppedWidth,
        height:croppedHeight
    });
    if (canvas != null){
        canvas.toBlob(function (blob) {
            let newImg = document.getElementById(imgId);
            const url = URL.createObjectURL(blob);
            newImg.addEventListener('load', () =>function() {
                URL.revokeObjectURL(url);
            });
            newImg.src = url;
        });
    }
    else {
        new PNotify({
            title: locales['error'],
            text: locales['imageError'],
            type: 'error',
            styling: 'bootstrap3',
            delay: 3000
        });
        cancel();
    }

}

function apply() {
    viewCroppedImage('image-cropped-preview2');
    $('#image-editor').addClass('hidden');
    cropper.getCroppedCanvas({
        width:croppedWidth,
        height:croppedHeight
    }).toBlob(function (blob) {
        imageBlob = blob;
        cropper.destroy();
        cropper = null;

    });
    document.getElementById('image-file').value = '';

}

function cancel() {
    imageBlob = null;
    cropper.destroy();
    cropper = null;
    $('#image-editor').addClass('hidden');
    document.getElementById('image-file').value = '';
}


function nameIsValid() {
    if(name.value === ''){
        nameError.innerText = locales['nameRequired'];
        nameError.classList.remove('hidden');
        return false;
    }
    else {
        if(!/^[A-Z][a-z]{1,30}([\-][A-Z][a-z]{1,30}|)$/.test(name.value)) {
            nameError.innerText = locales['nameInvalid'];
            nameError.classList.remove('hidden');
            return false;
        }
        else {
            nameError.classList.add('hidden');
            return true;
        }
    }
}

function surnameIsValid() {
    if(surname.value === ''){
        surnameError.innerText = locales['surnameRequired'];
        surnameError.classList.remove('hidden');
        return false;
    }
    else {
        if(!/^[A-Z][a-z]{1,30}([\-][A-Z][a-z]{1,30}|)$/.test(surname.value)) {
            surnameError.innerText = locales['surnameInvalid'];
            surnameError.classList.remove('hidden');
            return false;
        }
        else {
            surnameError.classList.add('hidden');
            return true;
        }

    }
}

function phoneIsValid() {
    if(phoneNumber.value === ''){
        phoneNumberError.innerText = locales['phoneNumberRequired'];
        phoneNumberError.classList.remove('hidden');
        return false;
    }
    else {
        if(!/^(\+\d{12})$/.test(phoneNumber.value)){
            phoneNumberError.innerText = locales['phoneNumberInvalid'];
            phoneNumberError.classList.remove('hidden');
            return false;
        }
        else {
            phoneNumberError.classList.add('hidden');
            return true;
        }
    }
}


function passwordChanged() {
    return (!(newPassword.value === ''));
}
function isPasswordsMatches() {
    if (newPassword.value === newPasswordRepeat.value) {
        passwordDontMathesError.classList.add("hidden");
        return true;
    }
    else {
        passwordDontMathesError.classList.remove("hidden");
        return false;
    }
}

function oldPasswordSet() {
    if (password.value === ''){
        passwordRequiredError.classList.remove('hidden');
        return false;
    }
    else {
        passwordRequiredError.classList.add('hidden');
        return true;
    }
}

function isPasswordValid() {
    if((password.value === '')||(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{7,}$/.test(newPassword.value))){
        passwordError.classList.add('hidden');
        return true;
    }
    else {
        passwordError.innerText = locales['passwordInvalid'];
        passwordError.classList.remove('hidden');
        return false;
    }
}
function newPasswordIsValid() {
    passwordRequiredError.classList.add('hidden');
    passwordError.classList.add('hidden');
    passwordDontMathesError.classList.add('hidden');
    if ((password.value === '')&&(newPassword.value === '')&&(newPasswordRepeat.value==='')){
        return true;
    }
    return (isPasswordsMatches()&isPasswordValid()&oldPasswordSet())
}



function submit(event) {
    event.preventDefault();
    if (nameIsValid() &&
        surnameIsValid() &&
        phoneIsValid() &&
        newPasswordIsValid()
        ){
        let submitButton = $("#submit-button");
        submitButton.attr("disabled", true);
        let userDataDTO = {
            'name': name.value,
            'surname': surname.value,
            'phoneNumber': phoneNumber.value,
        };

        let ajaxData = new FormData();
        ajaxData.append('userDataDTO', new Blob([JSON.stringify(userDataDTO)], {type: 'application/json;charset=UTF-8;'}));
        if (passwordChanged()){
            let newPasswordDTO = {
                'oldPassword':password.value,
                'newPassword':newPassword.value
            };
            ajaxData.append('newPasswordDTO',new Blob([JSON.stringify(newPasswordDTO)], {type: 'application/json;charset=UTF-8;'}));
        }
        if (imageBlob != null) {
            ajaxData.append('image', imageBlob);
        }

        $.ajax({
            url: profileUpdateURL,
            method: "POST",
            data: ajaxData,
            processData: false,
            contentType: false,
            success(response) {
                PNotify.removeAll();
                new PNotify({
                    title: locales['success'],
                    text: response.message,
                    type: 'success',
                    styling: 'bootstrap3'
                });

                cleanSessionStorage();
                initHeader();
                password.value ='';
                newPassword.value = '';
                newPasswordRepeat.value = '';
                imageBlob = null;
                submitButton.attr("disabled", false);

            },
            error(response) {
                submitButton.attr("disabled", false);
                PNotify.removeAll();
                switch (response.status){
                    case 400:
                        new PNotify({
                            title: locales['error'],
                            text: response.responseJSON.message,
                            type: 'error',
                            styling: 'bootstrap3',
                            delay:3000
                        });
                        break;
                    default:
                        new PNotify({
                            title: locales['error'],
                            text: locales['unexpectedError'],
                            type: 'error',
                            styling: 'bootstrap3',
                            delay:3000
                        });
                        break;
                }

            },

        });
    }
    else {
        PNotify.removeAll();
        new PNotify({
            title: locales['error'],
            text: locales['fieldsInvalid'],
            type: 'error',
            styling: 'bootstrap3'
        });
    }
}

function sendForgetPassword() {
    let btnReset = $("#reset-password-button");
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

function initProfilePage() {
    name = document.getElementById('name');
    surname = document.getElementById('surname');
    email = document.getElementById('email');
    phoneNumber = document.getElementById('phone-number');
    document.getElementById('user-info-form').addEventListener('submit',submit);
    newPassword = document.getElementById('new-password');
    newPasswordRepeat = document.getElementById('password-repeat');
    password = document.getElementById('password');
    //Init error paragraphs
    nameError  = document.getElementById('name-error');
    surnameError  = document.getElementById('surname-error');
    phoneNumberError  = document.getElementById('phone-number-error');
    passwordError  = document.getElementById('password-error');
    passwordError = document.getElementById('password-error');
    passwordRequiredError = document.getElementById('password-required-error');
    passwordDontMathesError = document.getElementById('password-error-matches');
    getUserFromServer();

}

$(document).ready(function(){
    initProfilePage();
});