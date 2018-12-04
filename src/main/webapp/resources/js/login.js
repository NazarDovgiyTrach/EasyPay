class Login {
    constructor() {
        this.homePageUrl = '/home';
        this.authorizationUrl = '/authorization';
        this.emailUrl = '/reactivationToken';
        this.loginForm = document.getElementById('loginForm');
        this.email = document.getElementById('email');
        this.loader = document.getElementById('loading');
        this.password = document.getElementById('password');
        this.reactivationTokenBtn = document.getElementById('redirect-btn');
        this.modalText = document.getElementById('message-text');
    }

    initListeners() {
        this.loginForm.addEventListener('submit', this.authorization.bind(this));
        this.reactivationTokenBtn.addEventListener('click', this.sendReactivationToken.bind(this));
    }

    getAuthorizationInfo() {
        return {
            email: this.email.value,
            password: this.password.value
        };
    }

    authorization(event) {
        event.preventDefault();
        let responseStatus;
        fetch(this.authorizationUrl, {
            method: 'POST',
            body: JSON.stringify(this.getAuthorizationInfo()),
            headers: {
                'Content-Type': 'application/json'
            }
        })
            .then(response => {
                responseStatus = response.status;
                return response.json();
            })
            .then(data => {
                if (responseStatus === 403) {
                    this.errorNotify(data.message);
                    return;
                }
                console.log(data);
                this.checkStatus(data);
            });
    }

    triggerModal(data) {
        this.modalText.innerHTML = this.modalInfo(data);
        $('#message-modal').modal('show');
    }

    modalInfo(data) {
        return `<p>${data.message}</p>`;
    }

    checkStatus(data) {
        switch (data.status) {
            case 'BANNED':
                this.errorNotify(data.message);
                break;
            case 'NOT_ACTIVE':
                this.triggerModal(data);
                break;
            case 'REGISTERED_BY_ADMIN':
                this.triggerModal(data);
                break;
            case 'ACTIVE':
                window.location.href = this.homePageUrl;
                break;
        }
    }

    sendReactivationToken() {
        event.preventDefault();
        $('#message-modal').modal('hide');
        this.show(this.loader);
        this.hide(this.loginForm);
        fetch(this.emailUrl, {
            method: 'POST',
            body: JSON.stringify(this.getAuthorizationInfo()),
            headers: {
                'Content-Type': 'application/json'
            }
        })
            .then(response => {
                console.log(response.status);
                return response.json();
            })
            .then(data => {
                console.log(data);
                this.hide(this.loader);
                this.show(this.loginForm);
                this.successNotify(data.message);
            });
    }

    successNotify(message) {
        PNotify.removeAll();
        new PNotify({
            title: locales['success'],
            text: message,
            type: 'success',
            styling: 'bootstrap3'
        });
    }

    errorNotify(message) {
        PNotify.removeAll();
        new PNotify({
            title: locales['error'],
            text: message,
            type: 'error',
            styling: 'bootstrap3'
        });
    }


    show(object) {
        object.classList.remove('hide');
        object.classList.add('show');
    }

    hide(object) {
        object.classList.remove('show');
        object.classList.add('hide');
    }
}

(function () {
    let login = new Login();
    login.initListeners();

    let urlParams = new URLSearchParams(window.location.search);
    if (urlParams.has('logout')) {
        login.successNotify(locales['logoutSuccess']);
    } else if (urlParams.has('resetPassword')) {
        login.successNotify(locales['resetPasswordSuccess']);
    } else if(urlParams.has("accountBanned")){
        login.errorNotify(locales['accountIsBanned']);
    } else if(urlParams.has("socialError")){
        login.errorNotify(locales['socialLoginError']);
    } else if(urlParams.has("registrationSuccess")){
        login.successNotify(locales['successConfirmation']);
    }
}());


