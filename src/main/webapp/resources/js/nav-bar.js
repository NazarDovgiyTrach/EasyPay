const myProfileURLForHeader = '/profile/my';
const avatarURL = '/profile/avatar';
let imageListenerSet = false;

function initHeader() {
    let fullName = sessionStorage.getItem('fullName');
    let role = sessionStorage.getItem('role');
    if ((fullName != null) && (role != null)) {
        document.getElementById('user-menu-header').classList.remove('hidden');
        document.getElementById('display-name').innerText = fullName;
        setAvatar();
    }
    else {
        getUserFromServerForHeader();
    }
}

function setAvatar() {
    let avatar = sessionStorage.getItem('avatar');
    if (avatar != null) {
        document.getElementById('user-avatar-header').src = sessionStorage.getItem('avatar');
    }
    else {
        addListenerToAvatarImg();
    }
}


function getMenuFromRole() {
    let role = sessionStorage.getItem('role');
    let menu = [];
    let localisationItems = [
        {'label': 'EN', 'reference': '?lang=en'},
        {'label': 'UA', 'reference': '?lang=ua'}
    ];
    let language = locales['language'];
    let roleLocalized = null;

    switch (role) {
        case 'USER':
            roleLocalized = locales['user'];
            menu.push(
                {'label': locales['addresses'], 'icon': 'fa fa-building-o', 'reference': '/user/addresses'},
                {
                    'label': locales['connectedUtilities'], 'icon': 'fa fa-tasks', 'reference':
                        '/user/connected-utilities/'
                },
                {'label': locales['payments'], 'icon': 'fa fa-money', 'reference': '/user/paymentsPage'},
                {
                    'label': locales['paymentsHistory'],
                    'icon': 'fa fa-history',
                    'reference': '/user/paymentsHistoryPage'
                },
                {'label': locales['rateInspectors'], 'icon': 'fa fa-star', 'reference': '/user/rate/'}
            );

            break;
        case 'MANAGER':
            roleLocalized = locales['manager'];
            menu.push(
                {'label': locales['inspectors'], 'icon': 'fa fa-table', 'reference': '/manager/schedule/'},
                {'label': locales['utilityPrice'], 'icon': 'fa fa-tasks', 'reference':
                        '/manager/utility/price'
                }
            );
            break;
        case 'INSPECTOR':
            roleLocalized = locales['inspector'];
            menu.push(
                {'label': locales['schedule'], 'icon': 'fa fa-table', 'reference': '/inspector/schedule/'},
                {'label': locales['checkCounters'], 'icon': 'fa fa-pencil', 'reference':
                        '/inspector/addresses/counters/'
                },
                {'label': locales['rateClients'], 'icon': 'fa fa-star', 'reference': '/inspector/rate/'}
            );
            break;
        case 'ADMIN':
            roleLocalized = locales['admin'];
            menu.push(
                {'label': locales['utilities'], 'icon': 'fa fa-tasks', 'reference': '/admin/utilitiesPage'},
                {'label': locales['users'], 'icon': 'fa fa-users', 'reference':
                        '/admin/management-users'
                },
                {'label': locales['registerUser'], 'icon': 'fa fa-user', 'reference': '/admin/register-user'}
            );
            break;
        default:
            return false;
    }
    let responseMap = {'menu': menu, 'localisation': localisationItems, 'language': language, 'role': roleLocalized};

    setLanguageMenu(responseMap);
    setUserMenu(responseMap);
    return true;
}

function setNameAndAvatar(response) {
    let fullName = response.name + " " + response.surname;
    let role = response.role;
    sessionStorage.setItem('fullName', fullName);
    sessionStorage.setItem('role', role);
    document.getElementById('user-menu-header').classList.remove('hidden');
    document.getElementById('display-name').innerText = response.name + " " + response.surname;
    setAvatar();
}

function avatarImgListener() {
    let avatarImg = document.getElementById("user-avatar-header");
    let imgCanvas = document.createElement("canvas"),
        imgContext = imgCanvas.getContext("2d");
    imgCanvas.width = avatarImg.width;
    imgCanvas.height = avatarImg.height;
    imgContext.drawImage(avatarImg, 0, 0, avatarImg.width, avatarImg.height);
    let imgAsDataURL = imgCanvas.toDataURL("image/png");
    sessionStorage.setItem("avatar", imgAsDataURL);
}

function addListenerToAvatarImg() {
    let avatarImg = document.getElementById("user-avatar-header");
    avatarImg.crossOrigin = "Anonymous";
    if (imageListenerSet == false) {
        avatarImg.addEventListener("load", avatarImgListener, false);
        imageListenerSet = true;
    }
    avatarImg.src = avatarURL;
}

function cleanSessionStorage() {
    sessionStorage.removeItem('role');
    sessionStorage.removeItem('avatar');
    sessionStorage.removeItem('fullName');

}

function getUserFromServerForHeader() {
    $.ajax({
        type: "GET",
        url: myProfileURLForHeader,
        success: function (response) {
            setNameAndAvatar(response);
        }
    });
}


function setLanguageMenu(response) {
    let headerLI = document.createElement('li');
    headerLI.setAttribute("id", "language-dropdown");
    let dropdownA = document.createElement('a');
    dropdownA.href = "javascript:;";
    dropdownA.classList.add("dropdown-toggle");
    dropdownA.classList.add("user-profile");
    dropdownA.setAttribute("data-toggle", "dropdown");
    dropdownA.setAttribute("aria-expanded", "false");
    let dropdownText = document.createElement('span');
    dropdownText.innerText = response.language;
    let dropdownIcon = document.createElement('span');
    dropdownIcon.classList.add("fa");
    dropdownIcon.classList.add("fa-angle-down");
    dropdownA.appendChild(dropdownText);
    dropdownA.appendChild(dropdownIcon);
    let dropdownMenu = document.createElement("ul");
    dropdownMenu.classList.add("dropdown-menu");
    dropdownMenu.classList.add("pull-right");
    let dropdownMenuA;
    let dropdownMenuLI;
    let searchParams = new URLSearchParams(window.location.search);
    if (searchParams.has('lang')) {
        searchParams.delete('lang');
    }
    let params = searchParams.toLocaleString();
    if (params.length > 0) {
        params = '&' + params
    }
    for (let menuItem in response.localisation) {
        dropdownMenuLI = document.createElement('li');
        dropdownMenuA = document.createElement('a');
        dropdownMenuA.setAttribute("href", response.localisation[menuItem].reference + params);
        dropdownMenuA.innerText = response.localisation[menuItem].label;
        dropdownMenuLI.appendChild(dropdownMenuA);
        dropdownMenu.appendChild(dropdownMenuLI);
    }
    headerLI.appendChild(dropdownA);
    headerLI.appendChild(dropdownMenu);
    document.getElementById('user-menu-header').parentNode.appendChild(headerLI);
}

function setUserMenu(response) {
    let menuSection = document.createElement('div');
    menuSection.classList.add('menu_section');
    let role = document.createElement('h3');
    role.innerText = response.role;
    menuSection.appendChild(role);
    let ul = document.createElement('ul');
    ul.classList.add('nav');
    ul.classList.add('side-menu');
    let menuItemA;
    let menuItemIcon;
    let menuItemText;
    let menuItemLI;
    let url = window.location.href.split('#')[0].split('?')[0];
    for (let menuItem in response.menu) {
        menuItemLI = document.createElement('li');
        if (url.includes(response.menu[menuItem])) {
            menuItemLI.classList.add('current-page');
        }
        menuItemA = document.createElement('a');
        menuItemA.setAttribute("href", response.menu[menuItem].reference);
        menuItemIcon = document.createElement('i');
        menuItemIcon.setAttribute("class", response.menu[menuItem].icon);
        menuItemText = document.createElement('span');
        menuItemText.innerText = response.menu[menuItem].label;
        menuItemA.appendChild(menuItemIcon);
        menuItemA.appendChild(menuItemText);
        menuItemLI.appendChild(menuItemA);
        ul.appendChild(menuItemLI);
    }
    menuSection.appendChild(ul);
    let sidebarMenu = document.getElementById('sidebar-menu');
    while (sidebarMenu.firstChild) {
        sidebarMenu.removeChild(sidebarMenu.firstChild);
    }
    sidebarMenu.appendChild(menuSection);
}




let menuSetTimer = setInterval(function(){
    console.log('try');
    if ((sessionStorage.getItem('role') == null) || (locales == null)) {
        return;
    }
    if (getMenuFromRole() == false){
        sessionStorage.removeItem('role');
        getUserFromServerForHeader();
        return;
    }
    console.log('success');
    clearInterval(menuSetTimer);


}, 100);

$(document).ready(function () {
    initHeader();
});