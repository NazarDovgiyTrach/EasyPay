class Registration{
    constructor(){
        this.registrationForm = document.getElementById('userInfo');
        this.modalMessage = document.getElementById('message-text');
        this.url = '/registration';
        this.isErrorsExist = false;
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
        console.log(this.getUserInfo());
        let error = this.validateFields(this.getUserInfo());
        if(Object.keys(error).length === 0){
            fetch('/registration', {
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
                    console.log(data);
                    if (this.isErrorsExist) {
                        this.showMistakes(data);
                    } else {
                        this.clearMistakes();
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
            confirmation: this.confirmation.value,
        };
    }


     validateFields(data){
        let errors = {};
        if(data.name === ''){
            errors.name = "Name must contain at least 2 characters!";
        } else if(!/^[A-Z][a-z]{1,30}([\-][A-Z][a-z]{1,30}|)$/.test(data.name)){
            errors.name = "Name can contain only latin letters and - sign!";
        }

        if(data.surname === ''){
            errors.surname = "Surname must contain at least 2 characters!";
        } else if(!/^[A-Z][a-z]{1,30}([\-][A-Z][a-z]{1,30}|)$/.test(data.surname)){
            errors.surname = "Surname can contain only latin letters and - sign!";
        }

        if(data.phoneNumber === ''){
            errors.phoneNumber = "Phone number is required!";
        } else if(!/^(\+\d{12})$/.test(data.phoneNumber)){
            errors.phoneNumber = "First sign must be + then your full phone number!";
        }

        if(data.email === ''){
            errors.email = "Email field is required!";
        } else if(!/^\w{1,40}@\w{2,15}\.\w{2,15}$/.test(data.email)){
            errors.email = "Enter correct email address!";
        }

        if(data.password === ''){
            errors.password = "Password must contain at least 7 characters!";
        } else if(!/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{7,}$/.test(data.password)){
            errors.password ="Password must contain at least one uppercase character, one lowercase character and one digit!";
        }

        if(data.confirmation === ''){
            errors.confirm = "Confirm your password!";
        } else if(data.password !== data.confirmation){
            errors.confirm = "Your passwords must be equal!";
        }

        return errors;
    }

    triggerMessageModal(data) {
        this.modalMessage.innerText = data.message;
        $('#registerModal').modal('hide');
        $('#message-modal').modal('show');
    }

    showMistakes(error){
        this.clearMistakes();
        for(let element in error){
            console.log(element);
            this.errorObject[element].innerHTML = error[element];
            this.errorObject[element].classList.add('mistake');
        }
    }

    clearMistakes() {
        for(let element in this.errorObject){
            this.errorObject[element].innerHTML = '';
        }
    }

}

(function () {
    let registration = new Registration();
    registration.initListeners();
}());

