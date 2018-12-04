class Registration{
    constructor(){
        this.url = '/registration';
        this.isErrorsExist = false;
        this.registrationForm = document.getElementById('userInfo');
        this.modalMessage = document.getElementById('message-text');
        this.loader = document.getElementById('loading');
        this.mainFrom = document.getElementById('registration');
        this.modalBtn = document.getElementById('redirect-btn');
        this.name = document.getElementById('name');
        this.surname = document.getElementById('surname');
        this.phoneNumber = document.getElementById('phone');
        this.email = document.getElementById('email');
        this.password = document.getElementById('password');
        this.confirmation = document.getElementById('confirm');
        this.errorObject = {
            name: document.getElementById('nameErr'),
            surname: document.getElementById('surnameErr'),
            phoneNumber: document.getElementById('phoneErr'),
            email: document.getElementById('emailErr'),
            password: document.getElementById('passwordErr'),
            confirm: document.getElementById('confirmErr')
        };
    }

    initListeners(){
        this.registrationForm.addEventListener('submit',  this.sendUserInfo.bind(this));
    }

    sendUserInfo(event){
        event.preventDefault();
        this.isErrorsExist = false;
        let error = this.validateFields(this.getUserInfo());
        if(Object.keys(error).length === 0){
            this.hideFormShowLoader();
            fetch(this.url, {
                method: 'POST',
                body: JSON.stringify(this.getUserInfo()),
                headers:{
                    'Content-Type': 'application/json'
                }
            })
            .then(response => {
                if(response.ok){
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

    getUserInfo(){
        return {
            name: this.name.value,
            surname: this.surname.value,
            phoneNumber: this.phoneNumber.value,
            email: this.email.value,
            password: this.password.value,
            confirmation: this.confirmation.value
        };
    }


     validateFields(data){
        let errors = {};
        if(data.name === ''){
            errors.name = locales['emptyName'];
        } else if(!/^[A-Z][a-z]{1,30}([\-][A-Z][a-z]{1,30}|)$/.test(data.name)){
            errors.name = locales['errorName'];
        }

        if(data.surname === ''){
            errors.surname = locales['emptySurname'];
        } else if(!/^[A-Z][a-z]{1,30}([\-][A-Z][a-z]{1,30}|)$/.test(data.surname)){
            errors.surname = locales['errorSurname'];
        }

        if(data.phoneNumber === ''){
            errors.phoneNumber = locales['emptyPhoneNumber'];
        } else if(!/^(\+\d{12})$/.test(data.phoneNumber)){
            errors.phoneNumber = locales['errorPhoneNumber'];
        }

        if(data.email === ''){
            errors.email = locales['emptyEmail'];
        } else if(!/^\w{1,40}@\w{2,15}\.\w{2,15}$/.test(data.email)){
            errors.email = locales['errorEmail'];
        }

        if(data.password === ''){
            errors.password = locales['emptyPassword'];
        } else if(!/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{7,}$/.test(data.password)){
            errors.password = locales['errorPassword'];
        }

        if(data.confirmation === ''){
            errors.confirm = locales['emptyPasswordConfirm'];
        } else if(data.password !== data.confirmation){
            errors.confirm = locales['errorConfirmPassword'];
        }

        return errors;
    }

    triggerMessageModal(data) {
        this.modalMessage.innerText = data.message;
        $('#message-modal').modal('show');
    }

    showMistakes(error){
        this.clearMistakes();
        for(let element in error){
            this.errorObject[element].innerHTML = error[element];
            this.errorObject[element].classList.add('mistake');
        }
    }

    clearMistakes() {
        for(let element in this.errorObject){
            this.errorObject[element].innerHTML = '';
        }
    }

    hideFormShowLoader(){
        this.mainFrom.classList.remove('show');
        this.mainFrom.classList.add('hide');
        this.loader.classList.remove('hide');
        this.loader.classList.add('show');
    }

    hideLoaderShowFrom(){
        this.loader.classList.remove('show');
        this.loader.classList.add('hide');
        this.mainFrom.classList.remove('hide');
        this.mainFrom.classList.add('show');
    }
}

(function () {
    let registration = new Registration();
    registration.initListeners();
}());

