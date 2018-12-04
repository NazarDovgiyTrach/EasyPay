class ContinueRegistration {
    constructor() {
        let urlParams = new URLSearchParams(window.location.search);
        this.registrationForm = document.getElementById('userInfo');
        this.modalMessage = document.getElementById('message-text');
        this.loader = document.getElementById('loading');
        this.mainFrom = document.getElementById('registration');
        this.url = '/finish-registration/?token=' + urlParams.get('token');
        this.isErrorsExist = false;
        this.modalBtn = document.getElementById('redirect-btn');
        this.name = document.getElementById('name');
        this.surname = document.getElementById('surname');
        this.phoneNumber = document.getElementById('phone');
        this.password = document.getElementById('password');
        this.confirmation = document.getElementById('confirm');
        this.errorObject = {
            name: document.getElementById('nameErr'),
            surname: document.getElementById('surnameErr'),
            phoneNumber: document.getElementById('phoneErr'),
        };
    }

    initListeners() {
        this.registrationForm.addEventListener('submit', this.sendUserInfo.bind(this));
    }

    sendUserInfo(event) {
        event.preventDefault();
        this.isErrorsExist = false;
        let error = this.validateFields(this.getUserInfo());
        if (Object.keys(error).length === 0) {
            this.hideFormShowLoader();
            fetch(this.url, {
                method: 'POST',
                body: JSON.stringify(this.getUserInfo()),
                headers: {
                    'Content-Type': 'application/json'
                }
            })
                .then(response => {
                    if (response.ok) {
                        this.modalBtn.setAttribute('href', '/');
                    } else {
                        this.isErrorsExist = true;
                    }
                    return response.json();
                })
                .then(data => {
                    if (this.isErrorsExist) {
                        this.hideLoaderShowFrom();
                        this.showMistakes(data);
                    } else {
                        this.clearMistakes();
                        this.hideLoaderShowFrom();
                        this.triggerMessageModal(data);
                    }
                });
        } else {
            this.showMistakes(error);
        }
    }

    getUserInfo() {
        return {
            name: this.name.value,
            surname: this.surname.value,
            phoneNumber: this.phoneNumber.value,
        };
    }


    validateFields(data) {
        let errors = {};
        if (data.name === '') {
            errors.name = "Name must contain at least 2 characters!";
        } else if (!/^[A-Z][a-z]{1,30}([\-][A-Z][a-z]{1,30}|)$/.test(data.name)) {
            errors.name = "Name can contain only latin letters and - sign!";
        }

        if (data.surname === '') {
            errors.surname = "Surname must contain at least 2 characters!";
        } else if (!/^[A-Z][a-z]{1,30}([\-][A-Z][a-z]{1,30}|)$/.test(data.surname)) {
            errors.surname = "Surname can contain only latin letters and - sign!";
        }

        if (data.phoneNumber === '') {
            errors.phoneNumber = "Phone number is required!";
        } else if (!/^(\+\d{12})$/.test(data.phoneNumber)) {
            errors.phoneNumber = "First sign must be + then your full phone number!";
        }

        return errors;
    }

    triggerMessageModal(data) {
        this.modalMessage.innerText = data.message;
        $('#message-modal').modal('show');
    }

    showMistakes(error) {
        this.clearMistakes();
        for (let element in error) {
            this.errorObject[element].innerHTML = error[element];
            this.errorObject[element].classList.add('mistake');
        }
    }

    clearMistakes() {
        for (let element in this.errorObject) {
            this.errorObject[element].innerHTML = '';
        }
    }

    hideFormShowLoader() {
        this.mainFrom.classList.remove('show');
        this.mainFrom.classList.add('hide');
        this.loader.classList.remove('hide');
        this.loader.classList.add('show');
    }

    hideLoaderShowFrom() {
        this.loader.classList.remove('show');
        this.loader.classList.add('hide');
        this.mainFrom.classList.remove('hide');
        this.mainFrom.classList.add('show');
    }
}

(function () {
    let registration = new ContinueRegistration();
    registration.initListeners();
}());
