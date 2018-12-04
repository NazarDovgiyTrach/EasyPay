class AdminRegistration{
    constructor(){
        this.url = '/admin/registration';
        this.isErrorsExist = false;
        this.registrationForm = document.getElementById('userInfo');
        this.modalMessage = document.getElementById('message-text');
        this.loader = document.getElementById('loading');
        this.hideArea = document.getElementById('hide-area');
        this.email = document.getElementById('email');
        this.role = document.getElementById('role');
        this.errorObject = {
            email: document.getElementById('emailErr'),
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
                    if(!response.ok){
                        this.isErrorsExist = true;
                    }
                    return response.json();
                })
                .then(data => {
                    console.log(data);
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
            email: this.email.value,
            role: this.role.value
            };
    }


    validateFields(data){
        let errors = {};

        if(data.email === ''){
            errors.email = "Email field is required!";
        } else if(!/^\w{1,40}@\w{2,15}\.\w{2,15}$/.test(data.email)){
            errors.email = "Enter correct email address!";
        }

        return errors;
    }

    triggerMessageModal(data) {
        this.modalMessage.innerText = data.message;
        $('#message-modal').modal('show');
    }

    showMistakes(error){
        this.clearMistakes();
        console.log("Element " + error);
        this.errorObject.email.innerHTML = error.email;
        this.errorObject.email.classList.add('mistake');

    }

    clearMistakes() {
        this.errorObject.email.innerHTML = '';
    }

    hideFormShowLoader(){
        this.hideArea.classList.remove('show');
        this.hideArea.classList.add('hide');
        this.loader.classList.remove('hide');
        this.loader.classList.add('show');
    }

    hideLoaderShowFrom(){
        this.loader.classList.remove('show');
        this.loader.classList.add('hide');
        this.hideArea.classList.remove('hide');
        this.hideArea.classList.add('show');
    }
}

(function () {
    fetch('/roles')
        .then(function (response) {
            return response.json();
        })
        .then(function (data) {
            let select = "";
            console.log(data);
            data.forEach((element) => {
                select += addOption(element);
            });
            document.getElementById("role").innerHTML = select;
        });

    let registration = new AdminRegistration();
    registration.initListeners();
}());

function addOption(element) {
    return `<option>${element}</option>`
}

